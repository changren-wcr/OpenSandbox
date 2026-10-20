// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Collections.Generic;
using System.Text.Json;
using System.Linq;
using OpenSandbox.Core;
using OpenSandbox.Internal;
using OpenSandbox.Models;
using OpenSandbox.Services;

namespace OpenSandbox.Adapters;

internal sealed class EgressAdapter : IEgress, ICredentialVault
{
    // Same per-rule cap as the sidecar (policy.go maxPortsPerRule) and server.
    private const int MaxPortsPerRule = 256;

    private readonly HttpClientWrapper _client;

    public EgressAdapter(HttpClientWrapper client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public async Task<CredentialVaultState> CreateAsync(
        IReadOnlyList<Credential> credentials,
        IReadOnlyList<CredentialBinding> bindings,
        CancellationToken cancellationToken = default)
    {
        var request = new CredentialVaultCreateRequest
        {
            Credentials = credentials,
            Bindings = bindings
        };

        return await _client.PostAsync<CredentialVaultState>(
            "/credential-vault",
            request,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<CredentialVaultState> GetAsync(CancellationToken cancellationToken = default)
    {
        return await _client.GetAsync<CredentialVaultState>(
            "/credential-vault",
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<CredentialVaultState> PatchAsync(
        CredentialVaultPatchRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request == null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return await _client.PatchAsync<CredentialVaultState>(
            "/credential-vault",
            request,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(CancellationToken cancellationToken = default)
    {
        await _client.DeleteAsync("/credential-vault", cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CredentialMetadata>> ListCredentialsAsync(
        CancellationToken cancellationToken = default)
    {
        var response = await _client.GetAsync<CredentialListResponse>(
            "/credential-vault/credentials",
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return response.Credentials;
    }

    public async Task<CredentialMetadata> GetCredentialAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetAsync<CredentialMetadata>(
            $"/credential-vault/credentials/{EncodePathSegment(name)}",
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<CredentialBindingMetadata>> ListBindingsAsync(
        CancellationToken cancellationToken = default)
    {
        var response = await _client.GetAsync<CredentialBindingListResponse>(
            "/credential-vault/bindings",
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return response.Bindings;
    }

    public async Task<CredentialBindingMetadata> GetBindingAsync(
        string name,
        CancellationToken cancellationToken = default)
    {
        return await _client.GetAsync<CredentialBindingMetadata>(
            $"/credential-vault/bindings/{EncodePathSegment(name)}",
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }

    public async Task<NetworkPolicy> GetPolicyAsync(CancellationToken cancellationToken = default)
    {
        var response = await _client.GetAsync<JsonElement>("/policy", cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!response.TryGetProperty("policy", out var policyElement) || policyElement.ValueKind != JsonValueKind.Object)
        {
            throw new SandboxApiException("Missing policy in egress response");
        }

        return ParseNetworkPolicy(policyElement);
    }

    public async Task PatchRulesAsync(
        IReadOnlyList<NetworkRule> rules,
        CancellationToken cancellationToken = default)
    {
        // target/ports are omitted (not sent as null) when unset, matching the
        // wire shape the sidecar/other SDKs produce for a port-only rule.
        var normalizedRules = rules.Select(r =>
        {
            ValidateNetworkRule(r);
            var normalized = new Dictionary<string, object?>
            {
                ["action"] = r.Action == NetworkRuleAction.Allow ? "allow" : "deny",
            };
            if (r.Target is not null)
            {
                normalized["target"] = r.Target;
            }
            if (r.Ports is not null)
            {
                normalized["ports"] = r.Ports;
            }
            return normalized;
        }).ToList();

        await _client.PatchAsync("/policy", normalizedRules, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteRulesAsync(
        IReadOnlyList<string> targets,
        CancellationToken cancellationToken = default)
    {
        await _client.DeleteAsync("/policy", targets.ToList(), cancellationToken).ConfigureAwait(false);
    }

    // Mirrors the server/sidecar checks so an invalid rule fails at the call
    // site with InvalidArgumentException instead of as a remote 400, matching
    // the client-side validation the Kotlin and Python SDKs already perform.
    private static void ValidateNetworkRule(NetworkRule rule)
    {
        // With Target optional, a rule with neither field is easy to build by mistake.
        if (rule.Target is null && rule.Ports is not { Count: > 0 })
        {
            throw new InvalidArgumentException("NetworkRule requires target, ports, or both.");
        }
        if (rule.Ports is null)
        {
            return;
        }
        // An explicitly empty Ports list used to be dropped silently, which
        // widened the rule to every port of the target. Reject it instead
        // (the spec declares `minItems: 1`).
        if (rule.Ports.Count == 0)
        {
            throw new InvalidArgumentException("NetworkRule ports cannot be empty; omit it (null) instead.");
        }
        if (rule.Ports.Count > MaxPortsPerRule)
        {
            throw new InvalidArgumentException($"NetworkRule ports cannot exceed {MaxPortsPerRule} entries.");
        }
        var seen = new HashSet<int>();
        foreach (var port in rule.Ports)
        {
            if (port < 1 || port > 65535)
            {
                throw new InvalidArgumentException($"NetworkRule port {port} out of range 1-65535.");
            }
            if (!seen.Add(port))
            {
                throw new InvalidArgumentException($"NetworkRule has duplicate port {port}.");
            }
        }
    }

    private static NetworkPolicy ParseNetworkPolicy(JsonElement element)
    {
        var policy = new NetworkPolicy();

        if (element.TryGetProperty("defaultAction", out var defaultAction) &&
            defaultAction.ValueKind == JsonValueKind.String)
        {
            policy.DefaultAction = ParseNetworkRuleAction(defaultAction.GetString());
        }

        if (element.TryGetProperty("egress", out var egress) &&
            egress.ValueKind == JsonValueKind.Array)
        {
            policy.Egress = egress.EnumerateArray().Select(ParseNetworkRule).ToList();
        }

        return policy;
    }

    private static NetworkRule ParseNetworkRule(JsonElement element)
    {
        var actionText = element.GetProperty("action").GetString();

        // The sidecar marshals target without omitempty, so a port-only rule
        // arrives as `"target": ""`; other producers may omit the key entirely.
        // Normalize both (and whitespace-only) to null so Target consistently
        // means "no target" for port-only rules.
        string? target = null;
        if (element.TryGetProperty("target", out var targetElement) &&
            targetElement.ValueKind == JsonValueKind.String)
        {
            var targetText = targetElement.GetString();
            target = string.IsNullOrWhiteSpace(targetText) ? null : targetText;
        }

        List<int>? ports = null;
        if (element.TryGetProperty("ports", out var portsElement) &&
            portsElement.ValueKind == JsonValueKind.Array)
        {
            // TryGetInt32 instead of GetInt32: a string, fractional or null
            // element would otherwise escape as a raw System.Text.Json
            // exception rather than the SDK's own API exception.
            ports = new List<int>();
            foreach (var portElement in portsElement.EnumerateArray())
            {
                if (portElement.ValueKind != JsonValueKind.Number || !portElement.TryGetInt32(out var port))
                {
                    throw new SandboxApiException($"Invalid network rule port: {portElement.GetRawText()}");
                }
                ports.Add(port);
            }
            // An empty list carries no port scope; treat it like an absent key.
            if (ports.Count == 0)
            {
                ports = null;
            }
        }

        return new NetworkRule
        {
            Action = ParseNetworkRuleAction(actionText),
            Target = target,
            Ports = ports
        };
    }

    private static NetworkRuleAction ParseNetworkRuleAction(string? action)
    {
        return action?.ToLowerInvariant() switch
        {
            "allow" => NetworkRuleAction.Allow,
            "deny" => NetworkRuleAction.Deny,
            _ => throw new SandboxApiException($"Invalid network rule action: {action ?? "<null>"}")
        };
    }

    private static string EncodePathSegment(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        return Uri.EscapeDataString(value);
    }
}
