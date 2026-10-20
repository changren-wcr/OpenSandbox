/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.opensandbox.sandbox.infrastructure.adapters.converter

import com.alibaba.opensandbox.sandbox.infrastructure.adapters.converter.SandboxModelConverter.toDomainEgressNetworkRule
import com.alibaba.opensandbox.sandbox.infrastructure.adapters.converter.SandboxModelConverter.toDomainNetworkRule
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import com.alibaba.opensandbox.sandbox.api.models.NetworkRule as ApiNetworkRule
import com.alibaba.opensandbox.sandbox.api.models.egress.NetworkRule as ApiEgressNetworkRule

/**
 * Read-back of rules the server/sidecar actually returns. The sidecar marshals
 * `target` without omitempty, so a port-only rule arrives as `"target": ""`;
 * the strict domain builder must not make such responses unreadable.
 */
class NetworkRuleConverterTest {
    @Test
    fun `egress rule with blank target and ports reads back as port-only`() {
        val rule =
            ApiEgressNetworkRule(
                action = ApiEgressNetworkRule.Action.deny,
                target = "",
                ports = listOf(25),
            ).toDomainEgressNetworkRule()

        assertNull(rule.target)
        assertEquals(listOf(25), rule.ports)
    }

    @Test
    fun `egress rule with target and empty ports reads back as not port-scoped`() {
        val rule =
            ApiEgressNetworkRule(
                action = ApiEgressNetworkRule.Action.allow,
                target = "10.0.0.5",
                ports = emptyList(),
            ).toDomainEgressNetworkRule()

        assertEquals("10.0.0.5", rule.target)
        assertNull(rule.ports)
    }

    @Test
    fun `lifecycle rule with blank target and ports reads back as port-only`() {
        val rule =
            ApiNetworkRule(
                action = ApiNetworkRule.Action.allow,
                target = "",
                ports = listOf(443),
            ).toDomainNetworkRule()

        assertNull(rule.target)
        assertEquals(listOf(443), rule.ports)
    }

    @Test
    fun `lifecycle rule with target and empty ports reads back as not port-scoped`() {
        val rule =
            ApiNetworkRule(
                action = ApiNetworkRule.Action.deny,
                target = "example.com",
                ports = emptyList(),
            ).toDomainNetworkRule()

        assertEquals("example.com", rule.target)
        assertNull(rule.ports)
    }
}
