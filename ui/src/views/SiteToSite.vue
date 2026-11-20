<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <div class="page-header-row">
          <div>
            <h2>{{ $t("s2s.title") }}</h2>
            <p class="page-subtitle">{{ $t("s2s.subtitle") }}</p>
          </div>
        </div>
      </cv-column>
    </cv-row>

    <!-- Action feedback banner -->
    <cv-row v-if="feedbackBanner.visible" class="mg-bottom-md">
      <cv-column>
        <NsInlineNotification
          :kind="feedbackBanner.kind"
          :title="feedbackBanner.title"
          :description="feedbackBanner.description"
          :showCloseButton="true"
          @close="feedbackBanner.visible = false"
        />
      </cv-column>
    </cv-row>

    <!-- Toolbar -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true" class="s2s-toolbar-tile">
          <div class="s2s-toolbar">
            <div class="search-wrap">
              <cv-search
                v-model="searchQuery"
                :label="$t('common.search')"
                :placeholder="$t('s2s.search_placeholder')"
                :clear-aria-label="$t('common.clear_filter')"
                size="xl"
              />
            </div>

            <div class="toolbar-actions">
              <NsButton
                kind="secondary"
                size="field"
                :icon="Renew20"
                :loading="loading.listTunnels"
                :disabled="loading.listTunnels"
                @click="listTunnels"
              >
                {{ $t("s2s.refresh") }}
              </NsButton>

              <NsButton
                kind="primary"
                size="field"
                :icon="Add20"
                :disabled="loading.listTunnels"
                @click="openCreateModal"
              >
                {{ $t("s2s.add_tunnel") }}
              </NsButton>
            </div>
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Site-to-Site Tunnels Table -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true">
          <cv-data-table-skeleton
            v-if="loading.listTunnels"
            :columns="tableColumns"
            :rows="3"
          />

          <NsEmptyState
            v-else-if="!tunnels.length"
            :title="$t('s2s.empty_title')"
          >
            <template #pictogram>
              <ServerRackPictogram />
            </template>
            <template #description>
              <div>{{ $t("s2s.empty_description") }}</div>
              <div class="mg-top-md">
                <NsButton
                  kind="primary"
                  :icon="Add20"
                  @click="openCreateModal"
                >
                  {{ $t("s2s.add_tunnel") }}
                </NsButton>
              </div>
            </template>
          </NsEmptyState>

          <NsEmptyState
            v-else-if="!filteredTunnels.length"
            :title="$t('s2s.no_results_title')"
          >
            <template #description>
              <div>{{ $t("s2s.no_results_description") }}</div>
            </template>
          </NsEmptyState>

          <div v-else class="responsive-table-wrapper">
            <cv-data-table :columns="tableColumns">
              <template slot="data">
                <cv-data-table-row
                  v-for="tunnel in filteredTunnels"
                  :key="tunnel.id"
                  :value="tunnel.id"
                >
                  <!-- Branch / Tunnel Name -->
                  <cv-data-table-cell>
                    <div class="tunnel-name-cell">
                      <div class="tunnel-title-line">
                        <Router20 class="router-icon" />
                        <strong>{{ tunnel.name }}</strong>
                      </div>
                      <div
                        v-if="tunnel.public_key"
                        class="pubkey-preview monospace mg-top-xs"
                        :title="tunnel.public_key"
                      >
                        {{ shortenKey(tunnel.public_key) }}
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Tunnel IP & Remote Endpoint -->
                  <cv-data-table-cell>
                    <div class="monospace">{{ tunnel.assigned_ip }}</div>
                    <div class="endpoint-meta mg-top-xs">
                      <span v-if="tunnel.remote_endpoint" class="monospace">
                        {{ tunnel.remote_endpoint }}
                      </span>
                      <span v-else class="muted-text">
                        {{ $t("s2s.dynamic_endpoint") }}
                      </span>
                    </div>
                  </cv-data-table-cell>

                  <!-- Remote Subnets -->
                  <cv-data-table-cell>
                    <div class="cidrs-wrap">
                      <cv-tag
                        v-for="cidr in tunnel.remote_cidrs || []"
                        :key="cidr"
                        kind="blue"
                        :label="cidr"
                      />
                    </div>
                  </cv-data-table-cell>

                  <!-- Connection & Handshake -->
                  <cv-data-table-cell>
                    <div class="connection-indicator">
                      <span
                        class="dot"
                        :class="tunnel.online ? 'online' : 'offline'"
                      />
                      <span>
                        {{
                          tunnel.online
                            ? $t("peers.state_online")
                            : tunnel.last_handshake_at
                            ? $t("peers.state_offline")
                            : $t("peers.never_connected")
                        }}
                      </span>
                    </div>
                    <div
                      v-if="tunnel.last_handshake_at"
                      class="endpoint-meta mg-top-xs"
                    >
                      {{
                        $t("peers.last_handshake", {
                          time: formatHandshake(tunnel.last_handshake_at),
                        })
                      }}
                    </div>
                  </cv-data-table-cell>

                  <!-- Transfer Volume -->
                  <cv-data-table-cell>
                    <div class="traffic-cell monospace">
                      <div class="rx-line">
                        ↓ {{ formatBytes(tunnel.rx_bytes) }}
                      </div>
                      <div class="tx-line">
                        ↑ {{ formatBytes(tunnel.tx_bytes) }}
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Status -->
                  <cv-data-table-cell>
                    <cv-tag
                      v-if="tunnel.enabled"
                      kind="green"
                      :label="$t('common.enabled')"
                    />
                    <cv-tag
                      v-else
                      kind="warm-gray"
                      :label="$t('common.disabled')"
                    />
                  </cv-data-table-cell>

                  <!-- Row Actions -->
                  <cv-data-table-cell>
                    <div class="row-actions-group">
                      <cv-icon-button
                        kind="ghost"
                        size="sm"
                        :icon="Download20"
                        :label="$t('s2s.action_show_config')"
                        :disabled="loading.actionTunnelId === tunnel.id"
                        @click="openTunnelConfig(tunnel)"
                      />

                      <cv-overflow-menu
                        flip-menu
                        tip-position="left"
                        :aria-label="$t('peers.col_actions')"
                      >
                        <cv-overflow-menu-item
                          @click="openTunnelConfig(tunnel)"
                        >
                          <NsMenuItem
                            :icon="Document20"
                            :label="$t('s2s.action_show_config')"
                          />
                        </cv-overflow-menu-item>

                        <cv-overflow-menu-item @click="toggleTunnel(tunnel)">
                          <NsMenuItem
                            :icon="tunnel.enabled ? Locked20 : Unlocked20"
                            :label="
                              tunnel.enabled
                                ? $t('s2s.action_disable')
                                : $t('s2s.action_enable')
                            "
                          />
                        </cv-overflow-menu-item>

                        <NsMenuDivider />

                        <cv-overflow-menu-item
                          danger
                          @click="askDeleteTunnel(tunnel)"
                        >
                          <NsMenuItem
                            :icon="TrashCan20"
                            :label="$t('s2s.action_delete')"
                          />
                        </cv-overflow-menu-item>
                      </cv-overflow-menu>
                    </div>
                  </cv-data-table-cell>
                </cv-data-table-row>
              </template>
            </cv-data-table>
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Create Site-to-Site Tunnel Modal -->
    <NsModal
      size="default"
      :visible="createModal.visible"
      :primaryButtonDisabled="loading.createTunnel"
      :isLoading="loading.createTunnel"
      @modal-hidden="closeCreateModal"
      @primary-click="submitCreateTunnel"
    >
      <template slot="label">{{ $t("s2s.create_modal_label") }}</template>
      <template slot="title">{{ $t("s2s.create_modal_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent="submitCreateTunnel">
          <NsInlineNotification
            v-if="createModal.errorBanner"
            kind="error"
            :title="$t('error.validation_error')"
            :description="createModal.errorBanner"
            :showCloseButton="false"
            class="mg-bottom-md"
          />

          <NsTextInput
            v-model.trim="createModal.name"
            :label="$t('s2s.field_name')"
            :placeholder="$t('s2s.field_name_placeholder')"
            :helperText="$t('s2s.field_name_helper')"
            :invalidMessage="createModal.errors.name"
            class="mg-bottom-md"
          />

          <div class="mg-bottom-md">
            <cv-text-area
              v-model="createModal.remote_cidrs_text"
              :label="$t('s2s.field_remote_cidrs')"
              :rows="3"
              :placeholder="$t('s2s.field_remote_cidrs_placeholder')"
              :helper-text="$t('s2s.field_remote_cidrs_helper')"
              :invalid-message="createModal.errors.remote_cidrs"
            />
          </div>

          <NsTextInput
            v-model.trim="createModal.remote_endpoint"
            :label="$t('s2s.field_remote_endpoint')"
            :placeholder="$t('s2s.field_remote_endpoint_placeholder')"
            :helperText="$t('s2s.field_remote_endpoint_helper')"
            :invalidMessage="createModal.errors.remote_endpoint"
            class="mg-bottom-md"
          />

          <div class="mg-bottom-sm">
            <NsToggle
              v-model="createModal.autoGenerateKey"
              value="auto_generate_key"
              :label="$t('s2s.field_key_mode')"
            >
              <template slot="text-left">
                {{ $t("s2s.key_mode_manual") }}
              </template>
              <template slot="text-right">
                {{ $t("s2s.key_mode_auto") }}
              </template>
            </NsToggle>
            <div class="bx--form__helper-text">
              {{ $t("s2s.field_key_mode_helper") }}
            </div>
          </div>

          <NsTextInput
            v-if="!createModal.autoGenerateKey"
            v-model.trim="createModal.remote_public_key"
            :label="$t('s2s.field_remote_public_key')"
            :placeholder="$t('s2s.field_remote_public_key_placeholder')"
            :invalidMessage="createModal.errors.remote_public_key"
            class="mg-top-sm"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("s2s.create_modal_submit") }}
      </template>
    </NsModal>

    <!-- S2S Router Config (.conf) Modal -->
    <NsModal
      size="default"
      :visible="configModal.visible"
      @modal-hidden="closeConfigModal"
      @primary-click="downloadTunnelConf"
    >
      <template slot="label">{{ $t("s2s.config_modal_label") }}</template>
      <template slot="title">
        {{ $t("s2s.config_modal_title", { name: configModal.name }) }}
      </template>
      <template slot="content">
        <NsInlineNotification
          v-if="configModal.justCreated"
          kind="success"
          :title="$t('s2s.created_banner_title')"
          :description="$t('s2s.created_banner_description')"
          :showCloseButton="false"
          class="mg-bottom-md"
        />

        <NsInlineNotification
          v-else-if="!loading.getConfig && !configModal.has_private_key"
          kind="info"
          :description="$t('s2s.manual_key_notice')"
          :showCloseButton="false"
          class="mg-bottom-md"
        />

        <cv-skeleton-text
          v-if="loading.getConfig"
          :paragraph="true"
          :line-count="6"
        />

        <div v-else>
          <div class="kv-label mg-bottom-xs">
            {{ $t("s2s.config_preview_label") }}
          </div>
          <NsCodeSnippet
            :copyTooltip="$t('common.copy_to_clipboard')"
            :copyFeedback="$t('common.copied')"
            :moreText="$t('common.show_more')"
            :lessText="$t('common.show_less')"
            hideExpandButton
          >
            {{ configModal.config_text }}
          </NsCodeSnippet>
        </div>
      </template>
      <template slot="secondary-button">{{ $t("common.close") }}</template>
      <template slot="primary-button">
        {{ $t("peers.download_conf") }}
      </template>
    </NsModal>

    <!-- Delete Confirmation Modal -->
    <NsModal
      kind="danger"
      size="small"
      :visible="deleteModal.visible"
      :primaryButtonDisabled="loading.deleteTunnel"
      :isLoading="loading.deleteTunnel"
      @modal-hidden="closeDeleteModal"
      @primary-click="confirmDeleteTunnel"
    >
      <template slot="title">{{ $t("s2s.delete_modal_title") }}</template>
      <template slot="content">
        <p class="mg-bottom-sm">
          {{
            $t("s2s.delete_modal_question", {
              name: deleteModal.tunnel ? deleteModal.tunnel.name : "",
            })
          }}
        </p>
        <NsInlineNotification
          kind="warning"
          :description="$t('s2s.delete_modal_warning')"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("s2s.delete_modal_confirm") }}
      </template>
    </NsModal>
  </cv-grid>
</template>

<script>
import { mapState } from "vuex";
import {
  QueryParamService,
  PageTitleService,
  TaskService,
  IconService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import Renew20 from "@carbon/icons-vue/es/renew/20";
import Router20 from "@carbon/icons-vue/es/router/20";
import Unlocked20 from "@carbon/icons-vue/es/unlocked/20";
import {
  to,
  formatTransferBytes,
  formatRelativeHandshake,
  resolveValidationError,
} from "@/utils/ns8";

const IPV4_CIDR_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]?\d)$/;

export default {
  name: "SiteToSite",
  components: {
    Router20,
  },
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("s2s.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "s2s",
      },
      urlCheckInterval: null,
      Renew20,
      Unlocked20,
      tunnels: [],
      searchQuery: "",
      feedbackBanner: {
        visible: false,
        kind: "success",
        title: "",
        description: "",
      },
      createModal: {
        visible: false,
        name: "",
        remote_cidrs_text: "",
        remote_endpoint: "",
        autoGenerateKey: true,
        remote_public_key: "",
        errorBanner: "",
        errors: {
          name: "",
          remote_cidrs: "",
          remote_endpoint: "",
          remote_public_key: "",
        },
      },
      configModal: {
        visible: false,
        justCreated: false,
        tunnel_id: "",
        name: "",
        config_text: "",
        has_private_key: true,
      },
      deleteModal: {
        visible: false,
        tunnel: null,
      },
      loading: {
        listTunnels: false,
        createTunnel: false,
        getConfig: false,
        deleteTunnel: false,
        actionTunnelId: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    tableColumns() {
      return [
        this.$t("s2s.col_name"),
        this.$t("s2s.col_endpoint"),
        this.$t("s2s.col_remote_cidrs"),
        this.$t("peers.col_connection"),
        this.$t("peers.col_traffic"),
        this.$t("peers.col_status"),
        this.$t("peers.col_actions"),
      ];
    },
    filteredTunnels() {
      const needle = (this.searchQuery || "").trim().toLowerCase();
      if (!needle) {
        return this.tunnels;
      }
      return this.tunnels.filter((t) => {
        const haystack = [
          t.name,
          t.assigned_ip,
          t.remote_endpoint,
          ...(t.remote_cidrs || []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(needle);
      });
    },
  },
  watch: {
    instanceName(newVal, oldVal) {
      if (newVal && newVal !== oldVal) {
        this.listTunnels();
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
      this.listTunnels();
    }
  },
  methods: {
    formatBytes(val) {
      return formatTransferBytes(val);
    },
    formatHandshake(isoVal) {
      return formatRelativeHandshake(
        isoVal,
        this.$i18n.locale,
        this.$t("common.never"),
        this.$t("common.just_now")
      );
    },
    shortenKey(key) {
      if (!key || key.length <= 18) {
        return key || "";
      }
      return `${key.slice(0, 10)}…${key.slice(-6)}`;
    },
    splitCidrs(raw) {
      if (!raw) {
        return [];
      }
      return String(raw)
        .split(/[\n,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
    },
    async listTunnels() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.listTunnels = true;
      const taskAction = "list-s2s-tunnels";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.listTunnels = false;
      });
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, taskResult) => {
          const out = (taskResult && taskResult.output) || {};
          this.tunnels = Array.isArray(out.tunnels) ? out.tunnels : [];
          this.loading.listTunnels = false;
        }
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
        this.loading.listTunnels = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    openCreateModal() {
      this.createModal = {
        visible: true,
        name: "",
        remote_cidrs_text: "",
        remote_endpoint: "",
        autoGenerateKey: true,
        remote_public_key: "",
        errorBanner: "",
        errors: {
          name: "",
          remote_cidrs: "",
          remote_endpoint: "",
          remote_public_key: "",
        },
      };
    },
    closeCreateModal() {
      this.createModal.visible = false;
    },
    validateCreateForm() {
      this.createModal.errorBanner = "";
      Object.keys(this.createModal.errors).forEach((k) => {
        this.createModal.errors[k] = "";
      });
      let valid = true;

      if (!this.createModal.name || !this.createModal.name.trim()) {
        this.createModal.errors.name = this.$t("s2s.validation_name_required");
        valid = false;
      }

      const cidrs = this.splitCidrs(this.createModal.remote_cidrs_text);
      if (!cidrs.length) {
        this.createModal.errors.remote_cidrs = this.$t(
          "s2s.validation_cidrs_required"
        );
        valid = false;
      } else {
        const badCidr = cidrs.find((c) => !IPV4_CIDR_REGEX.test(c));
        if (badCidr) {
          this.createModal.errors.remote_cidrs = this.$t(
            "settings.validation_cidr_invalid",
            { value: badCidr }
          );
          valid = false;
        }
      }

      if (
        !this.createModal.autoGenerateKey &&
        (!this.createModal.remote_public_key ||
          !this.createModal.remote_public_key.trim())
      ) {
        this.createModal.errors.remote_public_key = this.$t(
          "s2s.validation_pubkey_required"
        );
        valid = false;
      }

      return valid;
    },
    async submitCreateTunnel() {
      if (!this.validateCreateForm()) {
        return;
      }
      if (!this.core || !this.instanceName) {
        return;
      }

      this.loading.createTunnel = true;
      const taskAction = "create-s2s-tunnel";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.createTunnel = false;
        this.createModal.errorBanner = this.$t("error.generic_error");
      });
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        (validationErrors) => {
          this.loading.createTunnel = false;
          const details = Array.isArray(validationErrors)
            ? validationErrors
            : validationErrors && Array.isArray(validationErrors.output)
            ? validationErrors.output
            : [];
          for (const item of details) {
            const param = (item.parameter || item.field || "").split(".")[0];
            const msg = resolveValidationError(this, "s2s", item);
            if (
              param &&
              Object.prototype.hasOwnProperty.call(
                this.createModal.errors,
                param
              )
            ) {
              this.createModal.errors[param] = msg;
            } else {
              this.createModal.errorBanner = msg;
            }
          }
        }
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, taskResult) => {
          this.loading.createTunnel = false;
          const out = (taskResult && taskResult.output) || {};
          const tunnel = out.tunnel || {};
          const tunnelName = tunnel.name || this.createModal.name;

          this.createModal.visible = false;
          this.configModal = {
            visible: true,
            justCreated: true,
            tunnel_id: tunnel.id || "",
            name: tunnelName,
            config_text: out.config_text || "",
            has_private_key: this.createModal.autoGenerateKey,
          };
          this.listTunnels();
        }
      );

      const payload = {
        name: this.createModal.name.trim(),
        remote_cidrs: this.splitCidrs(this.createModal.remote_cidrs_text),
        remote_endpoint: (this.createModal.remote_endpoint || "").trim(),
        remote_public_key: this.createModal.autoGenerateKey
          ? ""
          : (this.createModal.remote_public_key || "").trim(),
      };

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: payload,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.createTunnel = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    async openTunnelConfig(tunnel) {
      if (!this.core || !this.instanceName || !tunnel) {
        return;
      }
      this.configModal = {
        visible: true,
        justCreated: false,
        tunnel_id: tunnel.id,
        name: tunnel.name,
        config_text: "",
        has_private_key: true,
      };
      this.loading.getConfig = true;

      const taskAction = "get-s2s-config";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.getConfig = false;
        this.configModal.visible = false;
      });
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, taskResult) => {
          this.loading.getConfig = false;
          const out = (taskResult && taskResult.output) || {};
          this.configModal.config_text = out.config_text || "";
          this.configModal.has_private_key = Boolean(out.has_private_key);
          if (out.name) {
            this.configModal.name = out.name;
          }
        }
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            tunnel_id: tunnel.id,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.getConfig = false;
        this.configModal.visible = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    closeConfigModal() {
      this.configModal.visible = false;
    },
    downloadTunnelConf() {
      if (!this.configModal.config_text) {
        return;
      }
      const safeName = (this.configModal.name || "s2s-tunnel")
        .replace(/[^A-Za-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "");
      const filename = `${safeName || "s2s"}-wg.conf`;

      const blob = new Blob([this.configModal.config_text], {
        type: "text/plain;charset=utf-8",
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    },
    async toggleTunnel(tunnel) {
      if (!this.core || !this.instanceName || !tunnel) {
        return;
      }
      this.loading.actionTunnelId = tunnel.id;
      this.feedbackBanner.visible = false;
      const desiredEnabled = !tunnel.enabled;
      const taskAction = "toggle-s2s-tunnel";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.actionTunnelId = "";
      });
      this.core.$root.$once(`${taskAction}-completed-${eventId}`, () => {
        this.loading.actionTunnelId = "";
        this.feedbackBanner = {
          visible: true,
          kind: desiredEnabled ? "success" : "info",
          title: desiredEnabled
            ? this.$t("s2s.action_enable")
            : this.$t("s2s.action_disable"),
          description: desiredEnabled
            ? this.$t("s2s.enabled_banner", { name: tunnel.name })
            : this.$t("s2s.disabled_banner", { name: tunnel.name }),
        };
        this.listTunnels();
      });

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            tunnel_id: tunnel.id,
            enabled: desiredEnabled,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.actionTunnelId = "";
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    askDeleteTunnel(tunnel) {
      this.deleteModal = {
        visible: true,
        tunnel,
      };
    },
    closeDeleteModal() {
      this.deleteModal.visible = false;
      this.deleteModal.tunnel = null;
    },
    async confirmDeleteTunnel() {
      const target = this.deleteModal.tunnel;
      if (!this.core || !this.instanceName || !target) {
        return;
      }

      this.loading.deleteTunnel = true;
      this.feedbackBanner.visible = false;
      const taskAction = "delete-s2s-tunnel";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.deleteTunnel = false;
      });
      this.core.$root.$once(`${taskAction}-completed-${eventId}`, () => {
        this.loading.deleteTunnel = false;
        this.deleteModal.visible = false;
        this.deleteModal.tunnel = null;
        this.feedbackBanner = {
          visible: true,
          kind: "success",
          title: this.$t("s2s.delete_modal_title"),
          description: this.$t("s2s.deleted_banner", { name: target.name }),
        };
        this.listTunnels();
      });

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            tunnel_id: target.id,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.deleteTunnel = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
  },
};
</script>

<style scoped lang="scss">
.page-title {
  margin-top: 1.5rem;
}

.s2s-toolbar-tile {
  padding: 1rem;
}

.s2s-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;

  .search-wrap {
    flex: 1;
    min-width: 15rem;
    max-width: 28rem;
  }

  .toolbar-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }
}

.responsive-table-wrapper {
  width: 100%;
  overflow-x: auto;
}

.tunnel-name-cell {
  .tunnel-title-line {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;

    .router-icon {
      fill: #0f62fe;
      flex-shrink: 0;
    }
  }

  .pubkey-preview {
    font-size: 0.75rem;
    color: #525252;
  }
}

.endpoint-meta {
  font-size: 0.75rem;
  color: #525252;
}

.muted-text {
  color: #6f6f6f;
  font-style: italic;
}

.cidrs-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.traffic-cell {
  font-size: 0.8125rem;
  line-height: 1.4;

  .rx-line {
    color: #0f62fe;
  }

  .tx-line {
    color: #525252;
  }
}

.row-actions-group {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}
</style>
