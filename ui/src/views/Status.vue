<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("status.title") }}</h2>
      </cv-column>
    </cv-row>

    <!-- Unconfigured prompt banner -->
    <cv-row
      v-if="!loading.getConfiguration && !vpnConfig.configured"
      class="mg-bottom-md"
    >
      <cv-column>
        <NsInlineNotification
          kind="warning"
          :title="$t('status.not_configured_title')"
          :description="$t('status.not_configured_description')"
          :actionLabel="$t('status.open_settings')"
          @action="goToSettings"
          :showCloseButton="false"
        />
      </cv-column>
    </cv-row>

    <!-- Sync result inline banner -->
    <cv-row v-if="syncBanner.visible" class="mg-bottom-md">
      <cv-column>
        <NsInlineNotification
          :kind="syncBanner.kind"
          :title="syncBanner.title"
          :description="syncBanner.description"
          :showCloseButton="true"
          @close="syncBanner.visible = false"
        />
      </cv-column>
    </cv-row>

    <!-- VPN Live-Overview Card -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true" class="vpn-overview-card">
          <div class="vpn-overview-header">
            <div class="vpn-overview-title-wrap">
              <Vpn32 class="vpn-header-icon" />
              <h3>{{ $t("status.vpn_overview_title") }}</h3>
              <cv-tag
                v-if="!loading.getConfiguration"
                :kind="vpnConfig.tunnel_mode === 'full' ? 'purple' : 'blue'"
                :label="
                  vpnConfig.tunnel_mode === 'full'
                    ? $t('status.mode_full')
                    : $t('status.mode_split')
                "
              />
            </div>

            <div class="vpn-overview-actions">
              <NsButton
                kind="ghost"
                size="field"
                :icon="Events20"
                @click="goToPeers"
              >
                {{ $t("status.manage_peers") }}
              </NsButton>
              <NsButton
                kind="ghost"
                size="field"
                :icon="Network_220"
                @click="goToS2S"
              >
                {{ $t("s2s.title") }}
              </NsButton>
              <NsButton
                kind="secondary"
                size="field"
                :icon="Settings20"
                @click="goToSettings"
              >
                {{ $t("settings.title") }}
              </NsButton>
            </div>
          </div>

          <cv-skeleton-text
            v-if="loading.getConfiguration"
            :paragraph="true"
            :line-count="6"
            class="mg-top-md"
          />

          <template v-else>
            <!-- KPI Tiles -->
            <div class="kpi-grid mg-top-md mg-bottom-md">
              <div class="kpi-tile">
                <div class="kpi-label">
                  {{ $t("status.kpi_authorized_users") }}
                </div>
                <div class="kpi-value">{{ vpnSummary.authorized_users }}</div>
              </div>
              <div class="kpi-tile">
                <div class="kpi-label">{{ $t("status.kpi_total_peers") }}</div>
                <div class="kpi-value">{{ vpnSummary.total_peers }}</div>
              </div>
              <div class="kpi-tile kpi-online">
                <div class="kpi-label">{{ $t("status.kpi_online_peers") }}</div>
                <div class="kpi-value">
                  {{ totalOnlineConnections }}
                  <span v-if="vpnConfig.ovpn_enabled" class="kpi-sub">
                    (WG {{ vpnSummary.online_peers }} · OVPN
                    {{ vpnSummary.online_ovpn_clients }})
                  </span>
                </div>
              </div>
              <div class="kpi-tile">
                <div class="kpi-label">{{ $t("status.kpi_s2s_tunnels") }}</div>
                <div class="kpi-value">
                  {{ vpnSummary.active_s2s_tunnels }} /
                  {{ vpnSummary.s2s_tunnels }}
                </div>
              </div>
            </div>

            <!-- Live WireGuard attributes -->
            <div class="key-value-grid mg-bottom-md">
              <div class="kv-item">
                <div class="kv-label">{{ $t("status.active_interface") }}</div>
                <div class="kv-value monospace">
                  {{ vpnConfig.interface_name || defaultInterfaceName }}
                </div>
              </div>

              <div class="kv-item">
                <div class="kv-label">{{ $t("status.public_endpoint") }}</div>
                <div class="kv-value monospace">
                  <span v-if="vpnConfig.endpoint_host">
                    {{ vpnConfig.endpoint_host }}:{{ vpnConfig.wg_port }}/udp
                  </span>
                  <span v-else class="muted-text">
                    {{ $t("status.endpoint_not_set") }}
                  </span>
                </div>
              </div>

              <div class="kv-item">
                <div class="kv-label">{{ $t("status.transfer_subnet") }}</div>
                <div class="kv-value monospace">
                  {{ vpnConfig.wg_network || "10.199.0.0/24" }}
                </div>
              </div>

              <div class="kv-item">
                <div class="kv-label">{{ $t("status.tunnel_mode") }}</div>
                <div class="kv-value">
                  {{
                    vpnConfig.tunnel_mode === "full"
                      ? $t("status.mode_full")
                      : $t("status.mode_split")
                  }}
                </div>
              </div>
            </div>

            <!-- Self-Service Portal & OpenVPN Status Blocks -->
            <div
              v-if="vpnConfig.portal_enabled || vpnConfig.ovpn_enabled"
              class="feature-status-grid mg-bottom-md"
            >
              <!-- Self-Service Portal Card -->
              <div
                v-if="vpnConfig.portal_enabled"
                class="feature-subcard"
              >
                <div class="feature-subcard-title">
                  <strong>{{ $t("status.portal_card_title") }}</strong>
                  <cv-tag
                    :kind="portalTotpTagKind"
                    :label="portalTotpTagLabel"
                  />
                </div>
                <div class="mg-top-xs">
                  <cv-link
                    v-if="vpnConfig.portal_domain"
                    :href="`https://${vpnConfig.portal_domain}`"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="portal-external-link"
                  >
                    <span>https://{{ vpnConfig.portal_domain }}</span>
                    <Launch20 class="launch-inline-icon" />
                  </cv-link>
                  <span v-else class="muted-text">
                    {{ $t("status.endpoint_not_set") }}
                  </span>
                </div>
              </div>

              <!-- OpenVPN Fallback Card -->
              <div
                v-if="vpnConfig.ovpn_enabled"
                class="feature-subcard"
              >
                <div class="feature-subcard-title">
                  <strong>{{ $t("status.ovpn_card_title") }}</strong>
                  <cv-tag
                    :kind="vpnConfig.ovpn_totp_required ? 'green' : 'blue'"
                    :label="
                      vpnConfig.ovpn_totp_required
                        ? $t('status.ovpn_auth_ad_totp')
                        : $t('status.ovpn_auth_ad_only')
                    "
                  />
                </div>
                <div class="ovpn-meta-line mg-top-xs">
                  <span class="monospace">
                    {{ vpnConfig.ovpn_interface_name || defaultOvpnInterfaceName }}
                  </span>
                  <span>·</span>
                  <span class="monospace">
                    <template v-if="vpnConfig.endpoint_host">
                      {{ vpnConfig.endpoint_host }}:{{
                        vpnConfig.ovpn_public_port || vpnConfig.ovpn_port || 1194
                      }}/{{ vpnConfig.ovpn_proto || "tcp" }}
                    </template>
                    <template v-else>
                      {{
                        vpnConfig.ovpn_public_port || vpnConfig.ovpn_port || 1194
                      }}/{{ vpnConfig.ovpn_proto || "tcp" }}
                    </template>
                  </span>
                  <span>·</span>
                  <span class="monospace">
                    {{ vpnConfig.ovpn_network || "10.199.1.0/24" }}
                  </span>
                  <span>·</span>
                  <span>
                    {{
                      $t("status.ovpn_online_count", {
                        count: vpnSummary.online_ovpn_clients,
                      })
                    }}
                  </span>
                </div>
              </div>
            </div>

            <!-- Copyable Server Public Key -->
            <div class="server-pubkey-block mg-bottom-md">
              <div class="kv-label mg-bottom-xs">
                {{ $t("status.server_public_key") }}
              </div>
              <NsCodeSnippet
                v-if="vpnConfig.server_public_key"
                :copyTooltip="$t('common.copy_to_clipboard')"
                :copyFeedback="$t('common.copied')"
                :moreText="$t('common.show_more')"
                :lessText="$t('common.show_less')"
                hideExpandButton
              >
                {{ vpnConfig.server_public_key }}
              </NsCodeSnippet>
              <div v-else class="muted-text">
                {{ $t("status.no_public_key") }}
              </div>
            </div>

            <!-- Router / FritzBox Port-Forwarding Hint -->
            <NsInlineNotification
              kind="info"
              :title="$t('status.router_hint_title')"
              :description="routerForwardingHint"
              :showCloseButton="false"
              class="mg-bottom-md"
            />

            <!-- AD / LDAP Sync Sub-Panel -->
            <div class="ldap-sync-panel">
              <div class="ldap-sync-info">
                <h4>{{ $t("status.ldap_sync_card_title") }}</h4>
                <div class="ldap-meta-row mg-top-xs">
                  <div>
                    <span class="meta-label">
                      {{ $t("status.coupled_domain") }}:
                    </span>
                    <strong v-if="vpnConfig.user_domain">
                      {{ vpnConfig.user_domain }}
                      <span v-if="vpnConfig.vpn_group">
                        / {{ vpnConfig.vpn_group }}
                      </span>
                      <span v-else> ({{ $t("status.all_domain_users") }}) </span>
                    </strong>
                    <span v-else class="muted-text">
                      {{ $t("status.domain_not_configured") }}
                    </span>
                  </div>

                  <div>
                    <span class="meta-label">
                      {{ $t("status.last_synced_at") }}:
                    </span>
                    <span>{{ formattedLastSyncedAt }}</span>
                  </div>

                  <div class="sync-status-tag-wrap">
                    <span class="meta-label">
                      {{ $t("status.last_sync_status") }}:
                    </span>
                    <cv-tag
                      :kind="syncStatusTagKind"
                      :label="syncStatusLabel"
                    />
                  </div>
                </div>
                <div
                  v-if="vpnSummary.last_sync_error"
                  class="ns-error mg-top-xs sync-err-detail"
                >
                  {{ vpnSummary.last_sync_error }}
                </div>
              </div>

              <div class="ldap-sync-btn-wrap">
                <NsButton
                  kind="primary"
                  size="field"
                  :icon="Renew20"
                  :loading="loading.syncUsers"
                  :disabled="loading.syncUsers || !vpnConfig.user_domain"
                  @click="syncUsersNow"
                >
                  {{ $t("status.sync_now") }}
                </NsButton>
              </div>
            </div>
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Core NS8 Status Cards (Instance, Node, Backup, Logs) -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <div class="card-grid">
          <NsInfoCard
            light
            :title="status.instance || instanceName || '-'"
            :description="$t('status.app_instance')"
            :icon="Application32"
            :loading="loading.getStatus"
            class="ns-card"
          />

          <NsInfoCard
            light
            :title="installationNodeTitle"
            :description="$t('status.installation_node')"
            :icon="Chip32"
            :loading="loading.getStatus"
            class="ns-card"
          />

          <NsBackupCard
            v-if="core"
            :title="$t('status.backup')"
            :noBackupMessage="$t('status.no_backup')"
            :goToBackupLabel="$t('status.go_to_backup')"
            :repositoryLabel="$t('status.backup_repository')"
            :statusLabel="$t('status.backup_status')"
            :statusSuccessLabel="$t('status.backup_status_success')"
            :statusNotRunLabel="$t('status.backup_status_not_run')"
            :statusErrorLabel="$t('status.backup_status_error')"
            :completedLabel="$t('status.backup_completed')"
            :durationLabel="$t('status.backup_duration')"
            :totalSizeLabel="$t('status.backup_total_size')"
            :totalFileCountLabel="$t('status.backup_total_file_count')"
            :backupDisabledLabel="$t('status.backup_disabled')"
            :showMoreLabel="$t('common.show_more')"
            :multipleUncertainStatusLabel="$t('status.backup_uncertain')"
            :moduleId="instanceName"
            :moduleUiName="instanceLabel"
            :repositories="backupRepositories"
            :backups="backups"
            :loading="loading.listBackupRepositories || loading.listBackups"
            :coreContext="core"
            light
          />

          <NsSystemLogsCard
            v-if="core"
            :title="$t('status.system_logs')"
            :description="$t('status.system_logs_description')"
            :buttonLabel="$t('status.go_to_logs')"
            :router="core.$router"
            context="module"
            :moduleId="instanceName"
            light
          />
        </div>
      </cv-column>
    </cv-row>

    <!-- Systemd Services -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <h4 class="section-heading">
          {{ $tc("status.services", status.services.length) }}
        </h4>
        <div v-if="loading.getStatus" class="card-grid mg-top-sm">
          <cv-tile kind="standard" :light="true">
            <cv-skeleton-text :paragraph="true" :line-count="3" />
          </cv-tile>
        </div>
        <div v-else-if="!status.services.length" class="mg-top-sm">
          <cv-tile kind="standard" :light="true">
            <NsEmptyState :title="$t('status.no_services')" />
          </cv-tile>
        </div>
        <div v-else class="card-grid mg-top-sm">
          <NsSystemdServiceCard
            v-for="service in status.services"
            :key="service.name"
            light
            :serviceName="service.name"
            :active="service.active"
            :failed="service.failed"
            :enabled="service.enabled"
            :activeLabel="$t('status.service_active')"
            :inactiveLabel="$t('status.service_inactive')"
            :enabledLabel="$t('status.service_enabled')"
            :disaledLabel="$t('status.service_disabled')"
            :failedLabel="$t('status.service_failed')"
            :icon="Cube32"
          />
        </div>
      </cv-column>
    </cv-row>

    <!-- Container Images -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <h4 class="section-heading">
          {{ $tc("status.app_images", status.images.length) }}
        </h4>
        <cv-tile kind="standard" :light="true" class="mg-top-sm">
          <cv-skeleton-text
            v-if="loading.getStatus"
            :paragraph="true"
            :line-count="3"
          />
          <NsEmptyState
            v-else-if="!status.images.length"
            :title="$t('status.no_images')"
          />
          <NsDataTable
            v-else
            :allRows="status.images"
            :columns="imageColumns"
            :rawColumns="true"
            :isSearchable="false"
            :isLoading="false"
          >
            <template slot="data">
              <cv-data-table-row
                v-for="(img, idx) in status.images"
                :key="`${img.name}-${idx}`"
                :value="`${idx}`"
              >
                <cv-data-table-cell class="monospace">
                  {{ img.name }}
                </cv-data-table-cell>
                <cv-data-table-cell>
                  {{ formatImageSize(img.size) }}
                </cv-data-table-cell>
                <cv-data-table-cell>
                  {{ img.created || "-" }}
                </cv-data-table-cell>
              </cv-data-table-row>
            </template>
          </NsDataTable>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Persistent Volumes -->
    <cv-row v-if="status.volumes && status.volumes.length" class="mg-bottom-md">
      <cv-column>
        <h4 class="section-heading">
          {{ $tc("status.app_volumes", status.volumes.length) }}
        </h4>
        <cv-tile kind="standard" :light="true" class="mg-top-sm">
          <NsDataTable
            :allRows="status.volumes"
            :columns="volumeColumns"
            :rawColumns="true"
            :isSearchable="false"
            :isLoading="false"
          >
            <template slot="data">
              <cv-data-table-row
                v-for="(vol, idx) in status.volumes"
                :key="`${vol.name}-${idx}`"
                :value="`${idx}`"
              >
                <cv-data-table-cell class="monospace">
                  {{ vol.name }}
                </cv-data-table-cell>
                <cv-data-table-cell class="monospace">
                  {{ vol.mount || vol.mountpoint || "-" }}
                </cv-data-table-cell>
                <cv-data-table-cell>
                  {{ vol.created || "-" }}
                </cv-data-table-cell>
              </cv-data-table-row>
            </template>
          </NsDataTable>
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
import Vpn32 from "@carbon/icons-vue/es/VPN/32";
import Launch20 from "@carbon/icons-vue/es/launch/20";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import {
  to,
  goToAppPage,
  formatContainerImageSize,
  formatDateTimeSafe,
} from "@/utils/ns8";

export default {
  name: "Status",
  components: {
    Vpn32,
    Launch20,
  },
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("status.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "status",
      },
      urlCheckInterval: null,
      Renew20,
      status: {
        instance: "",
        services: [],
        images: [],
        volumes: [],
        node: null,
      },
      vpnConfig: {
        configured: true,
        endpoint_host: "",
        wg_port: 51820,
        wg_network: "10.199.0.0/24",
        tunnel_mode: "split",
        allowed_cidrs: [],
        dns_servers: [],
        dns_search_domain: "",
        server_public_key: "",
        interface_name: "",
        user_domain: "",
        vpn_group: "",
        portal_enabled: false,
        portal_domain: "",
        portal_lets_encrypt: false,
        portal_http2https: true,
        portal_totp_mode: "optional",
        ovpn_enabled: false,
        ovpn_proto: "tcp",
        ovpn_port: 1194,
        ovpn_public_port: 1194,
        ovpn_network: "10.199.1.0/24",
        ovpn_totp_required: false,
        ovpn_interface_name: "",
        host_lan_ip: "",
        host_lan_cidr: "",
        summary: {
          authorized_users: 0,
          total_peers: 0,
          active_peers: 0,
          online_peers: 0,
          online_ovpn_clients: 0,
          s2s_tunnels: 0,
          active_s2s_tunnels: 0,
          last_synced_at: null,
          last_sync_status: "never",
          last_sync_error: null,
        },
      },
      backupRepositories: [],
      backups: [],
      syncBanner: {
        visible: false,
        kind: "success",
        title: "",
        description: "",
      },
      loading: {
        getStatus: false,
        getConfiguration: false,
        syncUsers: false,
        listBackupRepositories: false,
        listBackups: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core", "appName"]),
    defaultInterfaceName() {
      return this.instanceName
        ? `wg-${this.instanceName}`.slice(0, 15)
        : "wg-vpn1";
    },
    defaultOvpnInterfaceName() {
      return this.instanceName
        ? `tun-${this.instanceName}`.slice(0, 15)
        : "tun-vpn1";
    },
    vpnSummary() {
      const s =
        this.vpnConfig && this.vpnConfig.summary ? this.vpnConfig.summary : {};
      return {
        authorized_users: s.authorized_users || 0,
        total_peers: s.total_peers || 0,
        active_peers: s.active_peers || 0,
        online_peers: s.online_peers || 0,
        online_ovpn_clients: s.online_ovpn_clients || 0,
        s2s_tunnels: s.s2s_tunnels || 0,
        active_s2s_tunnels: s.active_s2s_tunnels || 0,
        last_synced_at: s.last_synced_at || null,
        last_sync_status: s.last_sync_status || "never",
        last_sync_error: s.last_sync_error || null,
      };
    },
    totalOnlineConnections() {
      return (
        (this.vpnSummary.online_peers || 0) +
        (this.vpnConfig.ovpn_enabled
          ? this.vpnSummary.online_ovpn_clients || 0
          : 0)
      );
    },
    portalTotpTagKind() {
      if (this.vpnConfig.portal_totp_mode === "required") {
        return "green";
      }
      if (this.vpnConfig.portal_totp_mode === "disabled") {
        return "gray";
      }
      return "teal";
    },
    portalTotpTagLabel() {
      if (this.vpnConfig.portal_totp_mode === "required") {
        return this.$t("status.portal_totp_required");
      }
      if (this.vpnConfig.portal_totp_mode === "disabled") {
        return this.$t("status.portal_totp_disabled");
      }
      return this.$t("status.portal_totp_optional");
    },
    installationNodeTitle() {
      if (this.status && this.status.node) {
        return this.status.node_ui_name
          ? this.status.node_ui_name
          : `${this.$t("status.node")} ${this.status.node}`;
      }
      return "-";
    },
    routerForwardingHint() {
      const wgPort = this.vpnConfig.wg_port || 51820;
      const lanIp = this.vpnConfig.host_lan_ip;

      if (this.vpnConfig.ovpn_enabled) {
        const ovpnProto = (this.vpnConfig.ovpn_proto || "tcp").toUpperCase();
        const ovpnLocalPort = this.vpnConfig.ovpn_port || 1194;
        const ovpnPublicPort =
          this.vpnConfig.ovpn_public_port || ovpnLocalPort;
        if (lanIp) {
          return this.$t("status.router_hint_combined", {
            wgPort,
            lanIp,
            ovpnProto,
            ovpnPublicPort,
            ovpnLocalPort,
          });
        }
        return this.$t("status.router_hint_combined_no_ip", {
          wgPort,
          ovpnProto,
          ovpnPublicPort,
          ovpnLocalPort,
        });
      }

      if (lanIp) {
        return this.$t("status.router_hint_description", {
          port: wgPort,
          lanIp,
        });
      }
      return this.$t("status.router_hint_description_no_ip", { port: wgPort });
    },
    formattedLastSyncedAt() {
      return formatDateTimeSafe(
        this.vpnSummary.last_synced_at,
        this.$i18n.locale,
        this.$t("common.never")
      );
    },
    syncStatusTagKind() {
      switch (this.vpnSummary.last_sync_status) {
        case "ok":
          return "green";
        case "ldap_error":
          return "red";
        default:
          return "gray";
      }
    },
    syncStatusLabel() {
      switch (this.vpnSummary.last_sync_status) {
        case "ok":
          return this.$t("status.sync_status_ok");
        case "skipped":
          return this.$t("status.sync_status_skipped");
        case "ldap_error":
          return this.$t("status.sync_status_ldap_error");
        default:
          return this.$t("status.sync_status_never");
      }
    },
    imageColumns() {
      return [
        this.$t("status.name"),
        this.$t("status.size"),
        this.$t("status.created"),
      ];
    },
    volumeColumns() {
      return [
        this.$t("status.name"),
        this.$t("status.mount"),
        this.$t("status.created"),
      ];
    },
  },
  watch: {
    instanceName(newVal, oldVal) {
      if (newVal && newVal !== oldVal) {
        this.loadAllStatusData();
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
      this.loadAllStatusData();
    }
  },
  methods: {
    ...mapActions(["setInstanceStatusInStore", "setAppConfiguredInStore"]),
    loadAllStatusData() {
      this.getStatus();
      this.getConfiguration();
      this.listBackupRepositories();
      this.listBackups();
    },
    formatImageSize(size) {
      return formatContainerImageSize(
        size,
        this.$options.filters ? this.$options.filters.byteFormat : null
      );
    },
    goToSettings() {
      goToAppPage(this, "settings");
    },
    goToPeers() {
      goToAppPage(this, "peers");
    },
    goToS2S() {
      goToAppPage(this, "s2s");
    },
    async getStatus() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.getStatus = true;
      const taskAction = "get-status";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getStatusAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getStatusCompleted
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
        this.loading.getStatus = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getStatusCompleted(taskContext, taskResult) {
      const output = (taskResult && taskResult.output) || {};
      this.status = {
        instance: output.instance || this.instanceName,
        node: output.node || null,
        node_ui_name: output.node_ui_name || "",
        services: Array.isArray(output.services) ? output.services : [],
        images: Array.isArray(output.images) ? output.images : [],
        volumes: Array.isArray(output.volumes) ? output.volumes : [],
      };
      this.setInstanceStatusInStore(this.status);
      this.loading.getStatus = false;
    },
    getStatusAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getStatus = false;
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
      this.vpnConfig = {
        ...this.vpnConfig,
        ...cfg,
        summary: {
          ...this.vpnConfig.summary,
          ...(cfg.summary || {}),
        },
      };
      this.setAppConfiguredInStore(Boolean(cfg.configured));
      this.loading.getConfiguration = false;
    },
    getConfigurationAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getConfiguration = false;
    },
    async syncUsersNow() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.syncUsers = true;
      this.syncBanner.visible = false;
      const taskAction = "sync-users";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.syncUsersAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.syncUsersCompleted
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
        this.loading.syncUsers = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    syncUsersCompleted(taskContext, taskResult) {
      this.loading.syncUsers = false;
      const out = (taskResult && taskResult.output) || {};
      if (out.status === "ldap_error") {
        this.syncBanner = {
          visible: true,
          kind: "error",
          title: this.$t("status.sync_error_title"),
          description: out.message || this.$t("status.sync_status_ldap_error"),
        };
      } else if (out.status === "skipped") {
        this.syncBanner = {
          visible: true,
          kind: "warning",
          title: this.$t("status.sync_skipped_title"),
          description: out.message || this.$t("status.sync_status_skipped"),
        };
      } else {
        this.syncBanner = {
          visible: true,
          kind: "success",
          title: this.$t("status.sync_success_title"),
          description: this.$t("status.sync_success_description", {
            authorized: out.authorized_users || 0,
            active: out.active_peers || 0,
            suspended: out.suspended_peers || 0,
          }),
        };
      }
      this.getConfiguration();
    },
    syncUsersAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.syncUsers = false;
    },
    async listBackupRepositories() {
      if (!this.core) {
        return;
      }
      this.loading.listBackupRepositories = true;
      const taskAction = "list-backup-repositories";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listBackupRepositoriesAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listBackupRepositoriesCompleted
      );

      const [err] = await to(
        this.createClusterTaskForApp({
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listBackupRepositories = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listBackupRepositoriesCompleted(taskContext, taskResult) {
      const repos = (taskResult && taskResult.output) || [];
      this.backupRepositories = Array.isArray(repos)
        ? repos.sort(this.sortByProperty("name"))
        : [];
      this.loading.listBackupRepositories = false;
    },
    listBackupRepositoriesAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listBackupRepositories = false;
    },
    async listBackups() {
      if (!this.core) {
        return;
      }
      this.loading.listBackups = true;
      const taskAction = "list-backups";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listBackupsAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listBackupsCompleted
      );

      const [err] = await to(
        this.createClusterTaskForApp({
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listBackups = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listBackupsCompleted(taskContext, taskResult) {
      const out = (taskResult && taskResult.output) || {};
      const list = Array.isArray(out)
        ? out
        : Array.isArray(out.backups)
        ? out.backups
        : [];
      this.backups = list.sort(this.sortByProperty("name"));
      this.loading.listBackups = false;
    },
    listBackupsAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listBackups = false;
    },
  },
};
</script>

<style scoped lang="scss">
.page-title {
  margin-top: 1.5rem;
  margin-bottom: 1rem;
}

.vpn-overview-card {
  padding: 1.25rem;
}

.vpn-overview-header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;

  .vpn-overview-title-wrap {
    display: flex;
    align-items: center;
    gap: 0.75rem;

    h3 {
      margin: 0;
    }

    .vpn-header-icon {
      fill: #0f62fe;
      flex-shrink: 0;
    }
  }

  .vpn-overview-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
}

.kpi-sub {
  font-size: 0.8125rem;
  font-weight: 400;
  color: #525252;
  margin-left: 0.25rem;
}

.feature-status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
  gap: 1rem;
}

.feature-subcard {
  background-color: #f8f9fb;
  border: 1px solid #e0e0e0;
  padding: 0.875rem 1rem;

  .feature-subcard-title {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .portal-external-link {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-weight: 500;

    .launch-inline-icon {
      fill: currentColor;
    }
  }

  .ovpn-meta-line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.875rem;
    color: #161616;
  }
}

.ldap-sync-panel {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: 1rem;
  background-color: #f8f9fb;
  border: 1px solid #e0e0e0;

  h4 {
    margin: 0;
    font-size: 1rem;
  }

  .ldap-meta-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem 1.75rem;
    font-size: 0.875rem;

    .meta-label {
      color: #525252;
      margin-right: 0.35rem;
    }

    .sync-status-tag-wrap {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }
  }

  .sync-err-detail {
    font-size: 0.8125rem;
  }
}

.muted-text {
  color: #6f6f6f;
  font-style: italic;
}

.section-heading {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0;
}
</style>
