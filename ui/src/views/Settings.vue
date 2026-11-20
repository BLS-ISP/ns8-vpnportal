<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <div class="page-header-row">
          <div>
            <h2>{{ $t("settings.title") }}</h2>
            <p class="page-subtitle">{{ $t("settings.subtitle") }}</p>
          </div>
        </div>
      </cv-column>
    </cv-row>

    <!-- Saved inline notification -->
    <cv-row v-if="saveSuccessShown" class="mg-bottom-md">
      <cv-column>
        <NsInlineNotification
          kind="success"
          :title="$t('settings.saved_title')"
          :description="$t('settings.saved_description')"
          :showCloseButton="true"
          @close="saveSuccessShown = false"
        />
      </cv-column>
    </cv-row>

    <!-- Validation error summary notification -->
    <cv-row v-if="errors.formBanner" class="mg-bottom-md">
      <cv-column>
        <NsInlineNotification
          kind="error"
          :title="$t('error.validation_error')"
          :description="errors.formBanner"
          :showCloseButton="true"
          @close="errors.formBanner = ''"
        />
      </cv-column>
    </cv-row>

    <cv-row>
      <cv-column>
        <cv-tile kind="standard" :light="true" class="settings-form-tile">
          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="10"
          />

          <cv-form v-else @submit.prevent="configureModule">
            <!-- Section 1: User Management (NS8 AD / OpenLDAP) -->
            <section class="settings-section">
              <h3>{{ $t("settings.section_ldap_title") }}</h3>
              <p class="section-description">
                {{ $t("settings.section_ldap_description") }}
              </p>

              <NsInlineNotification
                v-if="!loading.listUserDomains && userDomains.length === 0"
                kind="warning"
                :description="$t('settings.no_user_domains_warning')"
                :showCloseButton="false"
                class="maxwidth mg-bottom-md"
              />

              <NsInlineNotification
                v-else-if="
                  !loading.getConfiguration &&
                  !loading.listUserDomains &&
                  userDomains.length > 0 &&
                  !form.user_domain
                "
                kind="warning"
                :title="$t('settings.user_domain_missing_banner_title')"
                :description="
                  $t('settings.user_domain_missing_banner_description')
                "
                :showCloseButton="false"
                class="maxwidth mg-bottom-md"
              />

              <div class="maxwidth mg-bottom-md">
                <NsComboBox
                  v-model="form.user_domain"
                  :title="$t('settings.user_domain')"
                  :label="$t('settings.user_domain_placeholder')"
                  :helperText="$t('settings.user_domain_helper')"
                  :warnText="userDomainWarnText"
                  :invalidMessage="errors.user_domain"
                  :options="userDomainOptions"
                  :disabled="loading.configureModule || loading.listUserDomains"
                  :autoFilter="true"
                  :autoHighlight="true"
                  :clearFilterLabel="$t('common.clear_filter')"
                  @filter="onUserDomainFilter"
                  showItemDescription
                  marginBottomOnOpen
                />
              </div>

              <div class="maxwidth mg-bottom-md">
                <NsComboBox
                  v-model="form.vpn_group"
                  :title="$t('settings.vpn_group')"
                  :label="
                    loading.listDomainGroups
                      ? $t('settings.loading_groups')
                      : $t('settings.vpn_group_placeholder')
                  "
                  :helperText="$t('settings.vpn_group_helper')"
                  :invalidMessage="errors.vpn_group"
                  :options="vpnGroupOptions"
                  :acceptUserInput="true"
                  :disabled="loading.configureModule"
                  :autoFilter="true"
                  :autoHighlight="true"
                  :clearFilterLabel="$t('common.clear_filter')"
                  :userInputLabel="$t('common.user_input')"
                  showItemDescription
                  marginBottomOnOpen
                />
              </div>

              <div class="two-col-fields maxwidth">
                <NsTextInput
                  v-model="form.sync_interval_minutes"
                  type="number"
                  min="1"
                  max="60"
                  step="1"
                  :label="$t('settings.sync_interval_minutes')"
                  :helperText="$t('settings.sync_interval_helper')"
                  :invalidMessage="errors.sync_interval_minutes"
                  :disabled="loading.configureModule"
                />

                <NsTextInput
                  v-model="form.max_devices_per_user"
                  type="number"
                  min="1"
                  max="20"
                  step="1"
                  :label="$t('settings.max_devices_per_user')"
                  :helperText="$t('settings.max_devices_helper')"
                  :invalidMessage="errors.max_devices_per_user"
                  :disabled="loading.configureModule"
                />
              </div>
            </section>

            <hr class="section-divider" />

            <!-- Section 2: Public VPN Endpoint & Router Hint -->
            <section class="settings-section">
              <h3>{{ $t("settings.section_endpoint_title") }}</h3>
              <p class="section-description">
                {{ $t("settings.section_endpoint_description") }}
              </p>

              <div class="maxwidth">
                <NsTextInput
                  v-model.trim="form.endpoint_host"
                  :label="$t('settings.endpoint_host')"
                  :placeholder="$t('settings.endpoint_host_placeholder')"
                  :helperText="$t('settings.endpoint_host_helper')"
                  :invalidMessage="errors.endpoint_host"
                  :disabled="loading.configureModule"
                  ref="endpointHostInput"
                />

                <NsTextInput
                  v-model="form.wg_port"
                  type="number"
                  min="1024"
                  max="65535"
                  step="1"
                  :label="$t('settings.wg_port')"
                  :helperText="$t('settings.wg_port_helper')"
                  :warnText="wgPortWarning"
                  :invalidMessage="errors.wg_port"
                  :disabled="loading.configureModule"
                />

                <NsInlineNotification
                  kind="info"
                  :title="$t('settings.router_box_title')"
                  :description="routerForwardingDescription"
                  :showCloseButton="false"
                  class="mg-top-sm mg-bottom-sm"
                />
              </div>
            </section>

            <hr class="section-divider" />

            <!-- Section 3: Network, Tunnel Mode & DNS -->
            <section class="settings-section">
              <h3>{{ $t("settings.section_network_title") }}</h3>
              <p class="section-description">
                {{ $t("settings.section_network_description") }}
              </p>

              <div class="maxwidth mg-bottom-md">
                <label class="bx--label">{{ $t("settings.tunnel_mode") }}</label>
                <cv-radio-group vertical>
                  <cv-radio-button
                    v-model="form.tunnel_mode"
                    name="tunnel_mode"
                    value="split"
                    :label="$t('settings.tunnel_mode_split')"
                    :disabled="loading.configureModule"
                  />
                  <cv-radio-button
                    v-model="form.tunnel_mode"
                    name="tunnel_mode"
                    value="full"
                    :label="$t('settings.tunnel_mode_full')"
                    :disabled="loading.configureModule"
                  />
                </cv-radio-group>
                <div class="bx--form__helper-text mg-top-xs">
                  {{
                    form.tunnel_mode === "full"
                      ? $t("settings.tunnel_mode_full_helper")
                      : $t("settings.tunnel_mode_split_helper")
                  }}
                </div>
              </div>

              <!-- Split-Tunnel Allowed CIDRs -->
              <div
                v-if="form.tunnel_mode === 'split'"
                class="maxwidth mg-bottom-md"
              >
                <div class="cidr-header-row">
                  <label class="bx--label" for="allowed-cidrs-textarea">
                    {{ $t("settings.allowed_cidrs") }}
                  </label>
                  <NsButton
                    v-if="hostLanCidr"
                    kind="ghost"
                    size="sm"
                    type="button"
                    :icon="Add20"
                    :disabled="loading.configureModule"
                    @click="insertDetectedHostLan"
                  >
                    {{
                      $t("settings.insert_host_lan_cidr", { cidr: hostLanCidr })
                    }}
                  </NsButton>
                </div>

                <cv-text-area
                  id="allowed-cidrs-textarea"
                  v-model="form.allowed_cidrs_text"
                  :rows="4"
                  :placeholder="$t('settings.allowed_cidrs_placeholder')"
                  :helper-text="$t('settings.allowed_cidrs_helper')"
                  :invalid-message="errors.allowed_cidrs"
                  :disabled="loading.configureModule"
                />
              </div>

              <div class="maxwidth">
                <NsTextInput
                  v-model="form.dns_servers_text"
                  :label="$t('settings.dns_servers')"
                  :placeholder="$t('settings.dns_servers_placeholder')"
                  :helperText="$t('settings.dns_servers_helper')"
                  :invalidMessage="errors.dns_servers"
                  :disabled="loading.configureModule"
                />

                <NsTextInput
                  v-model.trim="form.dns_search_domain"
                  :label="$t('settings.dns_search_domain')"
                  :placeholder="$t('settings.dns_search_domain_placeholder')"
                  :helperText="$t('settings.dns_search_domain_helper')"
                  :invalidMessage="errors.dns_search_domain"
                  :disabled="loading.configureModule"
                />
              </div>
            </section>

            <hr class="section-divider" />

            <!-- Section 4: End-User Self-Service Portal (Traefik & TOTP 2FA) -->
            <section class="settings-section">
              <h3>{{ $t("settings.section_portal_title") }}</h3>
              <p class="section-description">
                {{ $t("settings.section_portal_description") }}
              </p>

              <div class="maxwidth">
                <NsToggle
                  v-model="form.portal_enabled"
                  value="portal_enabled"
                  :label="$t('settings.portal_enabled')"
                  :disabled="loading.configureModule"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>

                <template v-if="form.portal_enabled">
                  <NsTextInput
                    v-model.trim="form.portal_domain"
                    :label="$t('settings.portal_domain')"
                    :placeholder="$t('settings.portal_domain_placeholder')"
                    :helperText="$t('settings.portal_domain_helper')"
                    :invalidMessage="errors.portal_domain"
                    :disabled="loading.configureModule"
                    class="mg-top-sm"
                  />

                  <div class="two-col-fields mg-top-sm mg-bottom-sm">
                    <NsToggle
                      v-model="form.portal_lets_encrypt"
                      value="portal_lets_encrypt"
                      :label="$t('settings.portal_lets_encrypt')"
                      :disabled="loading.configureModule"
                    >
                      <template slot="text-left">
                        {{ $t("common.disabled") }}
                      </template>
                      <template slot="text-right">
                        {{ $t("common.enabled") }}
                      </template>
                    </NsToggle>

                    <NsToggle
                      v-model="form.portal_http2https"
                      value="portal_http2https"
                      :label="$t('settings.portal_http2https')"
                      :disabled="loading.configureModule"
                    >
                      <template slot="text-left">
                        {{ $t("common.disabled") }}
                      </template>
                      <template slot="text-right">
                        {{ $t("common.enabled") }}
                      </template>
                    </NsToggle>
                  </div>

                  <div class="mg-top-sm">
                    <label class="bx--label">
                      {{ $t("settings.portal_totp_mode") }}
                    </label>
                    <cv-radio-group vertical>
                      <cv-radio-button
                        v-model="form.portal_totp_mode"
                        name="portal_totp_mode"
                        value="disabled"
                        :label="$t('settings.portal_totp_disabled')"
                        :disabled="loading.configureModule"
                      />
                      <cv-radio-button
                        v-model="form.portal_totp_mode"
                        name="portal_totp_mode"
                        value="optional"
                        :label="$t('settings.portal_totp_optional')"
                        :disabled="loading.configureModule"
                      />
                      <cv-radio-button
                        v-model="form.portal_totp_mode"
                        name="portal_totp_mode"
                        value="required"
                        :label="$t('settings.portal_totp_required')"
                        :disabled="loading.configureModule"
                      />
                    </cv-radio-group>
                    <div
                      v-if="errors.portal_totp_mode"
                      class="bx--form-requirement"
                    >
                      {{ errors.portal_totp_mode }}
                    </div>
                  </div>
                </template>
              </div>
            </section>

            <hr class="section-divider" />

            <!-- Section 5: OpenVPN Server (TCP/Hotel Fallback & Live Password Auth) -->
            <section class="settings-section">
              <h3>{{ $t("settings.section_ovpn_title") }}</h3>
              <p class="section-description">
                {{ $t("settings.section_ovpn_description") }}
              </p>

              <div class="maxwidth">
                <NsToggle
                  v-model="form.ovpn_enabled"
                  value="ovpn_enabled"
                  :label="$t('settings.ovpn_enabled')"
                  :disabled="loading.configureModule"
                >
                  <template slot="text-left">
                    {{ $t("common.disabled") }}
                  </template>
                  <template slot="text-right">
                    {{ $t("common.enabled") }}
                  </template>
                </NsToggle>

                <template v-if="form.ovpn_enabled">
                  <div class="mg-top-sm mg-bottom-md">
                    <label class="bx--label">
                      {{ $t("settings.ovpn_proto") }}
                    </label>
                    <cv-radio-group vertical>
                      <cv-radio-button
                        v-model="form.ovpn_proto"
                        name="ovpn_proto"
                        value="tcp"
                        :label="$t('settings.ovpn_proto_tcp')"
                        :disabled="loading.configureModule"
                      />
                      <cv-radio-button
                        v-model="form.ovpn_proto"
                        name="ovpn_proto"
                        value="udp"
                        :label="$t('settings.ovpn_proto_udp')"
                        :disabled="loading.configureModule"
                      />
                    </cv-radio-group>
                  </div>

                  <div class="two-col-fields">
                    <NsTextInput
                      v-model="form.ovpn_port"
                      type="number"
                      min="1"
                      max="65535"
                      step="1"
                      :label="$t('settings.ovpn_port')"
                      :helperText="$t('settings.ovpn_port_helper')"
                      :warnText="ovpnLocalPortWarning"
                      :invalidMessage="errors.ovpn_port"
                      :disabled="loading.configureModule"
                    />

                    <NsTextInput
                      v-model="form.ovpn_public_port"
                      type="number"
                      min="1"
                      max="65535"
                      step="1"
                      :label="$t('settings.ovpn_public_port')"
                      :helperText="$t('settings.ovpn_public_port_helper')"
                      :invalidMessage="errors.ovpn_public_port"
                      :disabled="loading.configureModule"
                    />
                  </div>

                  <NsInlineNotification
                    kind="info"
                    :title="$t('settings.ovpn_router_box_title')"
                    :description="ovpnRouterForwardingDescription"
                    :showCloseButton="false"
                    class="mg-top-xs mg-bottom-md"
                  />

                  <NsTextInput
                    v-model.trim="form.ovpn_network"
                    :label="$t('settings.ovpn_network')"
                    placeholder="10.199.1.0/24"
                    :helperText="$t('settings.ovpn_network_helper')"
                    :invalidMessage="errors.ovpn_network"
                    :disabled="loading.configureModule"
                  />

                  <div class="nat-toggle-block mg-top-sm">
                    <NsToggle
                      v-model="form.ovpn_totp_required"
                      value="ovpn_totp_required"
                      :label="$t('settings.ovpn_totp_required')"
                      :disabled="loading.configureModule"
                    >
                      <template slot="text-left">
                        {{ $t("common.disabled") }}
                      </template>
                      <template slot="text-right">
                        {{ $t("common.enabled") }}
                      </template>
                    </NsToggle>
                    <div class="bx--form__helper-text">
                      {{ $t("settings.ovpn_totp_required_helper") }}
                    </div>
                  </div>
                </template>
              </div>
            </section>

            <hr class="section-divider" />

            <!-- Section 6: Advanced Settings (CvAccordion) -->
            <section class="settings-section maxwidth">
              <cv-accordion>
                <cv-accordion-item :open="isAdvancedOpen">
                  <template slot="title">
                    <strong>{{ $t("settings.section_advanced_title") }}</strong>
                  </template>
                  <template slot="content">
                    <div class="mg-top-sm">
                      <NsTextInput
                        v-model.trim="form.wg_network"
                        :label="$t('settings.wg_network')"
                        placeholder="10.199.0.0/24"
                        :helperText="$t('settings.wg_network_helper')"
                        :invalidMessage="errors.wg_network"
                        :disabled="loading.configureModule"
                      />

                      <div class="nat-toggle-block mg-bottom-md">
                        <NsToggle
                          v-model="form.nat_enabled"
                          value="nat_enabled"
                          :label="$t('settings.nat_enabled')"
                          :disabled="loading.configureModule"
                        >
                          <template slot="text-left">
                            {{ $t("settings.nat_enabled_off") }}
                          </template>
                          <template slot="text-right">
                            {{ $t("settings.nat_enabled_on") }}
                          </template>
                        </NsToggle>
                        <div class="bx--form__helper-text">
                          {{ $t("settings.nat_enabled_helper") }}
                        </div>
                      </div>

                      <div class="two-col-fields">
                        <NsTextInput
                          v-model="form.wg_mtu"
                          type="number"
                          min="1280"
                          max="1420"
                          step="1"
                          :label="$t('settings.wg_mtu')"
                          :helperText="$t('settings.wg_mtu_helper')"
                          :invalidMessage="errors.wg_mtu"
                          :disabled="loading.configureModule"
                        />

                        <NsTextInput
                          v-model="form.persistent_keepalive"
                          type="number"
                          min="0"
                          max="300"
                          step="1"
                          :label="$t('settings.persistent_keepalive')"
                          :helperText="$t('settings.persistent_keepalive_helper')"
                          :invalidMessage="errors.persistent_keepalive"
                          :disabled="loading.configureModule"
                        />
                      </div>
                    </div>
                  </template>
                </cv-accordion-item>
              </cv-accordion>
            </section>

            <!-- Submit Button -->
            <div class="submit-bar mg-top-lg">
              <NsButton
                kind="primary"
                size="field"
                type="submit"
                :icon="Save20"
                :loading="loading.configureModule"
                :disabled="loading.configureModule || loading.getConfiguration"
              >
                {{ $t("common.save") }}
              </NsButton>
            </div>
          </cv-form>
        </cv-tile>
      </cv-column>
    </cv-row>
  </cv-grid>
</template>

<script>
import { mapState, mapActions } from "vuex";
import {
  QueryParamService,
  PageTitleService,
  TaskService,
  IconService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import { to, resolveValidationError } from "@/utils/ns8";

const IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV4_CIDR_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;

export default {
  name: "Settings",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("settings.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "settings",
      },
      urlCheckInterval: null,
      isInitialConfigLoad: false,
      configLoadedOnce: false,
      moduleConfigured: false,
      userDomainFilterText: "",
      isAdvancedOpen: false,
      saveSuccessShown: false,
      hostLanIp: "",
      hostLanCidr: "",
      clusterWgCidr: "10.5.4.0/24",
      clusterWgPort: 55820,
      userDomains: [],
      domainGroups: [],
      form: {
        user_domain: "",
        vpn_group: "",
        sync_interval_minutes: "5",
        max_devices_per_user: "3",
        endpoint_host: "",
        wg_port: "51820",
        tunnel_mode: "split",
        allowed_cidrs_text: "",
        dns_servers_text: "",
        dns_search_domain: "",
        portal_enabled: false,
        portal_domain: "",
        portal_lets_encrypt: false,
        portal_http2https: true,
        portal_totp_mode: "optional",
        ovpn_enabled: false,
        ovpn_proto: "tcp",
        ovpn_port: "1194",
        ovpn_public_port: "1194",
        ovpn_network: "10.199.1.0/24",
        ovpn_totp_required: false,
        wg_network: "10.199.0.0/24",
        nat_enabled: true,
        wg_mtu: "1380",
        persistent_keepalive: "25",
      },
      errors: {
        formBanner: "",
        user_domain: "",
        vpn_group: "",
        sync_interval_minutes: "",
        max_devices_per_user: "",
        endpoint_host: "",
        wg_port: "",
        tunnel_mode: "",
        allowed_cidrs: "",
        dns_servers: "",
        dns_search_domain: "",
        portal_domain: "",
        portal_totp_mode: "",
        ovpn_proto: "",
        ovpn_port: "",
        ovpn_public_port: "",
        ovpn_network: "",
        wg_network: "",
        wg_mtu: "",
        persistent_keepalive: "",
      },
      loading: {
        getConfiguration: false,
        listUserDomains: false,
        listDomainGroups: false,
        configureModule: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    userDomainOptions() {
      const options = this.userDomains.map((d) => {
        const schemaLabel = d.schema === "ad" ? "Active Directory" : "OpenLDAP";
        return {
          name: d.name,
          label: `${d.name} (${schemaLabel})`,
          value: d.name,
          description: d.base_dn || d.location || "",
        };
      });
      if (
        this.form.user_domain &&
        !options.some((opt) => opt.value === this.form.user_domain)
      ) {
        options.unshift({
          name: this.form.user_domain,
          label: this.form.user_domain,
          value: this.form.user_domain,
          description: "",
        });
      }
      return options;
    },
    vpnGroupOptions() {
      const options = this.domainGroups.map((g) => ({
        name: g.name,
        label: g.name,
        value: g.name,
        description: g.description || g.dn || "",
      }));
      if (
        this.form.vpn_group &&
        !options.some((opt) => opt.value === this.form.vpn_group)
      ) {
        options.unshift({
          name: this.form.vpn_group,
          label: this.form.vpn_group,
          value: this.form.vpn_group,
          description: "",
        });
      }
      return options;
    },
    userDomainWarnText() {
      if (
        !this.loading.getConfiguration &&
        !this.loading.listUserDomains &&
        this.userDomains.length > 0 &&
        !this.form.user_domain
      ) {
        return this.$t("settings.user_domain_unselected_warning");
      }
      return undefined;
    },
    wgPortWarning() {
      const portNum = Number(this.form.wg_port);
      if (portNum === 55820 || portNum === this.clusterWgPort) {
        return this.$t("settings.wg_port_cluster_warning");
      }
      return undefined;
    },
    ovpnLocalPortWarning() {
      const portNum = Number(this.form.ovpn_port);
      if (this.form.ovpn_proto === "tcp" && portNum === 443) {
        return this.$t("settings.ovpn_port_traefik_warning");
      }
      if (
        this.form.ovpn_proto === "udp" &&
        (portNum === 55820 || portNum === this.clusterWgPort)
      ) {
        return this.$t("settings.wg_port_cluster_warning");
      }
      return undefined;
    },
    routerForwardingDescription() {
      const port = Number(this.form.wg_port) || 51820;
      if (this.hostLanIp) {
        return this.$t("settings.router_box_description", {
          port,
          lanIp: this.hostLanIp,
        });
      }
      return this.$t("settings.router_box_description_no_ip", { port });
    },
    ovpnRouterForwardingDescription() {
      const proto = (this.form.ovpn_proto || "tcp").toUpperCase();
      const localPort = Number(this.form.ovpn_port) || 1194;
      const publicPort = Number(this.form.ovpn_public_port) || localPort;
      if (this.hostLanIp) {
        return this.$t("settings.ovpn_router_box_description", {
          proto,
          publicPort,
          localPort,
          lanIp: this.hostLanIp,
        });
      }
      return this.$t("settings.ovpn_router_box_description_no_ip", {
        proto,
        publicPort,
        localPort,
      });
    },
  },
  watch: {
    instanceName(newVal, oldVal) {
      if (newVal && newVal !== oldVal) {
        this.loadInitialSettings();
      }
    },
    "form.user_domain"(newDomain, oldDomain) {
      if (!newDomain) {
        this.domainGroups = [];
        return;
      }

      if (newDomain !== oldDomain) {
        this.listDomainGroups(newDomain);
      }

      // Auto-suggest DNS search domain from selected user_domain if empty
      if (!this.isInitialConfigLoad && !this.form.dns_search_domain) {
        const domainObj = this.userDomains.find((d) => d.name === newDomain);
        if (domainObj && domainObj.suggested_dns_search) {
          this.form.dns_search_domain = domainObj.suggested_dns_search;
        }
      }
    },
  },
  beforeRouteEnter(toRoute, fromRoute, next) {
    next((vm) => {
      if (vm.core) {
        vm.watchQueryData(vm);
        vm.urlCheckInterval = vm.initUrlBindingForApp(vm, vm.q.page);
      }
    });
  },
  beforeRouteLeave(toRoute, fromRoute, next) {
    if (this.urlCheckInterval) {
      clearInterval(this.urlCheckInterval);
    }
    next();
  },
  created() {
    if (this.core && this.instanceName) {
      this.loadInitialSettings();
    }
  },
  methods: {
    ...mapActions(["setAppConfiguredInStore"]),
    loadInitialSettings() {
      this.listUserDomains();
      this.getConfiguration();
    },
    splitListItems(rawText) {
      if (!rawText) {
        return [];
      }
      return String(rawText)
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean);
    },
    insertDetectedHostLan() {
      if (!this.hostLanCidr) {
        return;
      }
      const existing = this.splitListItems(this.form.allowed_cidrs_text);
      if (!existing.includes(this.hostLanCidr)) {
        existing.push(this.hostLanCidr);
        this.form.allowed_cidrs_text = existing.join("\n");
      }
    },
    resetValidationErrors() {
      Object.keys(this.errors).forEach((key) => {
        this.errors[key] = "";
      });
    },
    async getConfiguration() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.getConfiguration = true;
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getConfigurationAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getConfigurationCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.getConfiguration = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getConfigurationCompleted(taskContext, taskResult) {
      const cfg = (taskResult && taskResult.output) || {};
      this.isInitialConfigLoad = true;

      this.hostLanIp = cfg.host_lan_ip || "";
      this.hostLanCidr = cfg.host_lan_cidr || "";
      this.clusterWgCidr = cfg.cluster_wg_cidr || "10.5.4.0/24";
      this.clusterWgPort = cfg.cluster_wg_port || 55820;

      const allowedArr = Array.isArray(cfg.allowed_cidrs)
        ? cfg.allowed_cidrs
        : [];
      const dnsArr = Array.isArray(cfg.dns_servers) ? cfg.dns_servers : [];

      const totpMode = ["disabled", "optional", "required"].includes(
        cfg.portal_totp_mode
      )
        ? cfg.portal_totp_mode
        : "optional";

      this.form = {
        user_domain: cfg.user_domain || "",
        vpn_group: cfg.vpn_group || "",
        sync_interval_minutes: String(
          cfg.sync_interval_minutes !== undefined ? cfg.sync_interval_minutes : 5
        ),
        max_devices_per_user: String(
          cfg.max_devices_per_user !== undefined ? cfg.max_devices_per_user : 3
        ),
        endpoint_host: cfg.endpoint_host || "",
        wg_port: String(cfg.wg_port !== undefined ? cfg.wg_port : 51820),
        tunnel_mode: cfg.tunnel_mode === "full" ? "full" : "split",
        allowed_cidrs_text: allowedArr.join("\n"),
        dns_servers_text: dnsArr.join(", "),
        dns_search_domain: cfg.dns_search_domain || "",
        portal_enabled: Boolean(cfg.portal_enabled),
        portal_domain: cfg.portal_domain || "",
        portal_lets_encrypt: Boolean(cfg.portal_lets_encrypt),
        portal_http2https:
          cfg.portal_http2https !== undefined
            ? Boolean(cfg.portal_http2https)
            : true,
        portal_totp_mode: totpMode,
        ovpn_enabled: Boolean(cfg.ovpn_enabled),
        ovpn_proto: cfg.ovpn_proto === "udp" ? "udp" : "tcp",
        ovpn_port: String(cfg.ovpn_port !== undefined ? cfg.ovpn_port : 1194),
        ovpn_public_port: String(
          cfg.ovpn_public_port !== undefined ? cfg.ovpn_public_port : 1194
        ),
        ovpn_network: cfg.ovpn_network || "10.199.1.0/24",
        ovpn_totp_required: Boolean(cfg.ovpn_totp_required),
        wg_network: cfg.wg_network || "10.199.0.0/24",
        nat_enabled:
          cfg.nat_enabled !== undefined ? Boolean(cfg.nat_enabled) : true,
        wg_mtu: String(cfg.wg_mtu !== undefined ? cfg.wg_mtu : 1380),
        persistent_keepalive: String(
          cfg.persistent_keepalive !== undefined ? cfg.persistent_keepalive : 25
        ),
      };

      this.moduleConfigured = Boolean(cfg.configured);
      this.configLoadedOnce = true;
      this.setAppConfiguredInStore(Boolean(cfg.configured));
      this.loading.getConfiguration = false;
      this.maybeAutoSelectSingleDomain();

      this.$nextTick(() => {
        this.isInitialConfigLoad = false;
      });
    },
    getConfigurationAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getConfiguration = false;
    },
    onUserDomainFilter(val) {
      this.userDomainFilterText = typeof val === "string" ? val.trim() : "";
    },
    resolveTypedUserDomain() {
      if (this.form.user_domain || !this.userDomainFilterText) {
        return;
      }
      const typedLower = this.userDomainFilterText.toLowerCase();
      const matchedOpt = this.userDomainOptions.find(
        (opt) =>
          opt.value.toLowerCase() === typedLower ||
          opt.label.toLowerCase() === typedLower
      );
      if (matchedOpt) {
        this.form.user_domain = matchedOpt.value;
      }
    },
    maybeAutoSelectSingleDomain() {
      if (
        this.configLoadedOnce &&
        !this.moduleConfigured &&
        !this.form.user_domain &&
        this.userDomains.length === 1
      ) {
        const single = this.userDomains[0];
        this.form.user_domain = single.name;
        if (!this.form.dns_search_domain && single.suggested_dns_search) {
          this.form.dns_search_domain = single.suggested_dns_search;
        }
      }
    },
    async listUserDomains() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.listUserDomains = true;
      const taskAction = "list-user-domains";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listUserDomainsAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listUserDomainsCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listUserDomains = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listUserDomainsCompleted(taskContext, taskResult) {
      const out = (taskResult && taskResult.output) || {};
      this.userDomains = Array.isArray(out.domains) ? out.domains : [];
      this.loading.listUserDomains = false;

      this.maybeAutoSelectSingleDomain();

      if (this.form.user_domain && !this.form.dns_search_domain) {
        const matched = this.userDomains.find(
          (d) => d.name === this.form.user_domain
        );
        if (matched && matched.suggested_dns_search) {
          this.form.dns_search_domain = matched.suggested_dns_search;
        }
      }
    },
    listUserDomainsAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listUserDomains = false;
    },
    async listDomainGroups(domainName) {
      if (!this.core || !this.instanceName || !domainName) {
        return;
      }
      this.loading.listDomainGroups = true;
      const taskAction = "list-domain-groups";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listDomainGroupsAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listDomainGroupsCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            user_domain: domainName,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listDomainGroups = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listDomainGroupsCompleted(taskContext, taskResult) {
      const out = (taskResult && taskResult.output) || {};
      this.domainGroups = Array.isArray(out.groups) ? out.groups : [];
      this.loading.listDomainGroups = false;
    },
    listDomainGroupsAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listDomainGroups = false;
    },
    validateFormBeforeSubmit() {
      this.resetValidationErrors();
      let isValid = true;

      // 1. Endpoint host
      const host = (this.form.endpoint_host || "").trim();
      if (!host) {
        this.errors.endpoint_host = this.$t(
          "settings.validation_endpoint_required"
        );
        isValid = false;
      } else if (
        host.includes("://") ||
        host.includes("/") ||
        host.includes(" ") ||
        (host.includes(":") && !host.includes("::"))
      ) {
        this.errors.endpoint_host = this.$t(
          "settings.validation_endpoint_invalid"
        );
        isValid = false;
      }

      // 2. WireGuard UDP port
      const port = Number(this.form.wg_port);
      if (!Number.isInteger(port) || port < 1024 || port > 65535) {
        this.errors.wg_port = this.$t("settings.validation_port_range");
        isValid = false;
      } else if (port === 55820 || port === this.clusterWgPort) {
        this.errors.wg_port = this.$t("settings.validation_port_cluster");
        isValid = false;
      }

      // 3. Sync interval & Max devices
      const syncMin = Number(this.form.sync_interval_minutes);
      if (!Number.isInteger(syncMin) || syncMin < 1 || syncMin > 60) {
        this.errors.sync_interval_minutes = this.$t(
          "settings.validation_sync_range"
        );
        isValid = false;
      }

      const maxDev = Number(this.form.max_devices_per_user);
      if (!Number.isInteger(maxDev) || maxDev < 1 || maxDev > 20) {
        this.errors.max_devices_per_user = this.$t(
          "settings.validation_max_devices_range"
        );
        isValid = false;
      }

      // 4. Split-Tunnel CIDRs
      const cidrs = this.splitListItems(this.form.allowed_cidrs_text);
      if (this.form.tunnel_mode === "split") {
        if (!cidrs.length) {
          this.errors.allowed_cidrs = this.$t(
            "settings.validation_cidrs_required"
          );
          isValid = false;
        } else {
          const invalidCidr = cidrs.find((c) => !IPV4_CIDR_REGEX.test(c));
          if (invalidCidr) {
            this.errors.allowed_cidrs = this.$t(
              "settings.validation_cidr_invalid",
              { value: invalidCidr }
            );
            isValid = false;
          }
        }
      }

      // 5. DNS servers
      const dnsList = this.splitListItems(this.form.dns_servers_text);
      const invalidDns = dnsList.find((ip) => !IPV4_REGEX.test(ip));
      if (invalidDns) {
        this.errors.dns_servers = this.$t("settings.validation_dns_invalid", {
          value: invalidDns,
        });
        isValid = false;
      }

      // 6. Self-Service Portal validation
      if (this.form.portal_enabled) {
        const pDomain = (this.form.portal_domain || "").trim();
        if (
          !pDomain ||
          !pDomain.includes(".") ||
          pDomain.includes("://") ||
          pDomain.includes("/") ||
          pDomain.includes(" ")
        ) {
          this.errors.portal_domain = this.$t(
            "settings.validation_portal_domain_invalid"
          );
          isValid = false;
        }
      }

      // 7. OpenVPN validation
      const wgNet = (this.form.wg_network || "").trim();
      if (this.form.ovpn_enabled) {
        const ovpnPort = Number(this.form.ovpn_port);
        if (!Number.isInteger(ovpnPort) || ovpnPort < 1 || ovpnPort > 65535) {
          this.errors.ovpn_port = this.$t("error.invalid_port");
          isValid = false;
        } else if (
          this.form.ovpn_proto === "udp" &&
          (ovpnPort === 55820 || ovpnPort === this.clusterWgPort)
        ) {
          this.errors.ovpn_port = this.$t("settings.validation_port_cluster");
          isValid = false;
        } else if (this.form.ovpn_proto === "udp" && ovpnPort === port) {
          this.errors.ovpn_port = this.$t(
            "settings.validation_ovpn_port_wg_conflict"
          );
          isValid = false;
        }

        const ovpnPubPort = Number(this.form.ovpn_public_port);
        if (
          !Number.isInteger(ovpnPubPort) ||
          ovpnPubPort < 1 ||
          ovpnPubPort > 65535
        ) {
          this.errors.ovpn_public_port = this.$t("error.invalid_port");
          isValid = false;
        }

        const ovpnNet = (this.form.ovpn_network || "").trim();
        if (!IPV4_CIDR_REGEX.test(ovpnNet)) {
          this.errors.ovpn_network = this.$t(
            "settings.validation_wg_network_invalid"
          );
          isValid = false;
        } else if (
          ovpnNet === "10.5.4.0/24" ||
          ovpnNet === this.clusterWgCidr
        ) {
          this.errors.ovpn_network = this.$t(
            "settings.validation_wg_network_cluster"
          );
          isValid = false;
        } else if (ovpnNet === wgNet) {
          this.errors.ovpn_network = this.$t(
            "settings.validation_ovpn_wg_overlap"
          );
          isValid = false;
        } else if (cidrs.includes(ovpnNet)) {
          this.errors.ovpn_network = this.$t(
            "settings.validation_wg_network_overlap"
          );
          isValid = false;
        }
      }

      // 8. Advanced fields
      if (!IPV4_CIDR_REGEX.test(wgNet)) {
        this.errors.wg_network = this.$t(
          "settings.validation_wg_network_invalid"
        );
        this.isAdvancedOpen = true;
        isValid = false;
      } else if (wgNet === "10.5.4.0/24" || wgNet === this.clusterWgCidr) {
        this.errors.wg_network = this.$t(
          "settings.validation_wg_network_cluster"
        );
        this.isAdvancedOpen = true;
        isValid = false;
      } else if (cidrs.includes(wgNet)) {
        this.errors.wg_network = this.$t(
          "settings.validation_wg_network_overlap"
        );
        this.isAdvancedOpen = true;
        isValid = false;
      }

      const mtu = Number(this.form.wg_mtu);
      if (!Number.isInteger(mtu) || mtu < 1280 || mtu > 1420) {
        this.errors.wg_mtu = this.$t("settings.validation_mtu_range");
        this.isAdvancedOpen = true;
        isValid = false;
      }

      const keepalive = Number(this.form.persistent_keepalive);
      if (
        !Number.isInteger(keepalive) ||
        keepalive < 0 ||
        (keepalive > 0 && keepalive < 10) ||
        keepalive > 300
      ) {
        this.errors.persistent_keepalive = this.$t(
          "settings.validation_keepalive_range"
        );
        this.isAdvancedOpen = true;
        isValid = false;
      }

      return isValid;
    },
    async configureModule() {
      this.saveSuccessShown = false;
      this.resolveTypedUserDomain();
      if (!this.validateFormBeforeSubmit()) {
        return;
      }
      if (!this.core || !this.instanceName) {
        return;
      }

      this.loading.configureModule = true;
      const taskAction = "configure-module";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.configureModuleAborted
      );
      this.core.$root.$once(
        `${taskAction}-validation-ok-${eventId}`,
        this.configureModuleValidationOk
      );
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.configureModuleValidationFailed
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.configureModuleCompleted
      );

      const allowedCidrsArray = this.splitListItems(
        this.form.allowed_cidrs_text
      );
      const dnsServersArray = this.splitListItems(this.form.dns_servers_text);

      const payload = {
        endpoint_host: this.form.endpoint_host.trim(),
        wg_port: parseInt(this.form.wg_port, 10),
        wg_network: this.form.wg_network.trim(),
        tunnel_mode: this.form.tunnel_mode,
        allowed_cidrs: allowedCidrsArray,
        dns_servers: dnsServersArray,
        dns_search_domain: (this.form.dns_search_domain || "").trim(),
        wg_mtu: parseInt(this.form.wg_mtu, 10),
        persistent_keepalive: parseInt(this.form.persistent_keepalive, 10),
        nat_enabled: Boolean(this.form.nat_enabled),
        user_domain: (this.form.user_domain || "").trim(),
        vpn_group: (this.form.vpn_group || "").trim(),
        max_devices_per_user: parseInt(this.form.max_devices_per_user, 10),
        sync_interval_minutes: parseInt(this.form.sync_interval_minutes, 10),
        portal_enabled: Boolean(this.form.portal_enabled),
        portal_domain: (this.form.portal_domain || "").trim().toLowerCase(),
        portal_lets_encrypt: Boolean(this.form.portal_lets_encrypt),
        portal_http2https: Boolean(this.form.portal_http2https),
        portal_totp_mode: this.form.portal_totp_mode || "optional",
        ovpn_enabled: Boolean(this.form.ovpn_enabled),
        ovpn_proto: this.form.ovpn_proto === "udp" ? "udp" : "tcp",
        ovpn_port: parseInt(this.form.ovpn_port, 10) || 1194,
        ovpn_public_port: parseInt(this.form.ovpn_public_port, 10) || 1194,
        ovpn_network: (this.form.ovpn_network || "10.199.1.0/24").trim(),
        ovpn_totp_required: Boolean(this.form.ovpn_totp_required),
      };

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action." + taskAction),
            description: this.$t("common.processing"),
            eventId,
          },
        })
      );

      if (err) {
        this.loading.configureModule = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    configureModuleValidationOk() {
      // Validation succeeded; task continues executing 20configure & 80start_services
    },
    configureModuleValidationFailed(validationErrors) {
      this.loading.configureModule = false;
      this.resetValidationErrors();

      const details = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];

      const advancedFields = new Set([
        "wg_network",
        "wg_mtu",
        "persistent_keepalive",
      ]);

      for (const item of details) {
        const rawField = item.parameter || item.field || "";
        const normalizedField = rawField.split(".")[0];
        const message = resolveValidationError(this, "settings", item);

        if (
          normalizedField &&
          Object.prototype.hasOwnProperty.call(this.errors, normalizedField)
        ) {
          this.errors[normalizedField] = message;
          if (advancedFields.has(normalizedField)) {
            this.isAdvancedOpen = true;
          }
        } else {
          this.errors.formBanner = message;
        }
      }

      if (!this.errors.formBanner && details.length > 0) {
        this.errors.formBanner = this.$t("error.validation_error");
      }
    },
    configureModuleCompleted() {
      this.loading.configureModule = false;
      this.saveSuccessShown = true;
      this.setAppConfiguredInStore(true);
      this.getConfiguration();
    },
    configureModuleAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.configureModule = false;
    },
  },
};
</script>

<style scoped lang="scss">
.page-title {
  margin-top: 1.5rem;
}

.settings-form-tile {
  padding: 1.5rem;
}

.settings-section {
  h3 {
    margin: 0 0 0.35rem 0;
    font-size: 1.125rem;
    font-weight: 600;
  }

  .section-description {
    margin: 0 0 1.25rem 0;
    color: #525252;
    font-size: 0.875rem;
    max-width: 46rem;
    line-height: 1.45;
  }
}

.section-divider {
  border: 0;
  border-top: 1px solid #e0e0e0;
  margin: 1.75rem 0;
}

.two-col-fields {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
  gap: 1rem;
}

.cidr-header-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  margin-bottom: 0.25rem;

  .bx--label {
    margin-bottom: 0;
  }
}

.nat-toggle-block {
  margin-top: 0.5rem;
}

.submit-bar {
  padding-top: 0.5rem;
}
</style>
