<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <div class="page-header-row">
          <div>
            <h2>{{ $t("peers.title") }}</h2>
            <p class="page-subtitle">{{ $t("peers.subtitle") }}</p>
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

    <!-- Toolbar Row -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true" class="peers-toolbar-tile">
          <div class="peers-toolbar">
            <div class="toolbar-filters">
              <div class="search-wrap">
                <cv-search
                  v-model="searchQuery"
                  :label="$t('common.search')"
                  :placeholder="$t('peers.search_placeholder')"
                  :clear-aria-label="$t('common.clear_filter')"
                  size="xl"
                />
              </div>

              <div class="status-filter-wrap">
                <cv-select
                  v-model="statusFilter"
                  :label="$t('peers.filter_label')"
                  hideLabel
                >
                  <cv-select-option value="all">
                    {{ $t("peers.filter_all", { count: peers.length }) }}
                  </cv-select-option>
                  <cv-select-option value="online">
                    {{ $t("peers.filter_online", { count: countOnlinePeers }) }}
                  </cv-select-option>
                  <cv-select-option value="disabled">
                    {{
                      $t("peers.filter_disabled", { count: countDisabledPeers })
                    }}
                  </cv-select-option>
                  <cv-select-option value="unauthorized">
                    {{
                      $t("peers.filter_unauthorized", {
                        count: countUnauthorizedPeers,
                      })
                    }}
                  </cv-select-option>
                </cv-select>
              </div>
            </div>

            <div class="toolbar-actions">
              <NsButton
                kind="secondary"
                size="field"
                :icon="Renew20"
                :loading="loading.syncUsers"
                :disabled="loading.syncUsers || loading.listPeers"
                @click="syncUsers"
              >
                {{ $t("peers.sync_ldap") }}
              </NsButton>

              <NsButton
                kind="primary"
                size="field"
                :icon="Add20"
                :disabled="loading.listPeers"
                @click="openCreateModal('')"
              >
                {{ $t("peers.add_device") }}
              </NsButton>
            </div>
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Peers Table -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true">
          <cv-data-table-skeleton
            v-if="loading.listPeers"
            :columns="tableColumns"
            :rows="4"
          />

          <NsEmptyState
            v-else-if="!peers.length"
            :title="$t('peers.empty_title')"
          >
            <template #pictogram>
              <GroupPictogram />
            </template>
            <template #description>
              <div>{{ $t("peers.empty_description") }}</div>
              <div class="mg-top-md">
                <NsButton
                  kind="primary"
                  :icon="Add20"
                  @click="openCreateModal('')"
                >
                  {{ $t("peers.add_device") }}
                </NsButton>
              </div>
            </template>
          </NsEmptyState>

          <NsEmptyState
            v-else-if="!filteredPeers.length"
            :title="$t('peers.no_results_title')"
          >
            <template #description>
              <div>{{ $t("peers.no_results_description") }}</div>
            </template>
          </NsEmptyState>

          <div v-else class="responsive-table-wrapper">
            <cv-data-table :columns="tableColumns">
              <template slot="data">
                <cv-data-table-row
                  v-for="peer in filteredPeers"
                  :key="peer.id"
                  :value="peer.id"
                >
                  <!-- User & 2FA Badge -->
                  <cv-data-table-cell>
                    <div class="peer-user-cell">
                      <div class="peer-user-primary">
                        {{ peer.display_name || peer.username }}
                      </div>
                      <div
                        v-if="
                          peer.display_name &&
                          peer.display_name !== peer.username
                        "
                        class="peer-user-sub monospace"
                      >
                        {{ peer.username }}
                      </div>
                      <div class="user-badges-row mg-top-xs">
                        <cv-tag
                          v-if="peer.user_authorized"
                          kind="green"
                          :label="$t('peers.badge_authorized')"
                        />
                        <cv-tag
                          v-else
                          kind="red"
                          :label="$t('peers.badge_unauthorized')"
                        />

                        <cv-tag
                          v-if="isUserTotpEnrolled(peer.username)"
                          kind="teal"
                          :label="$t('peers.badge_totp_active')"
                        />
                        <cv-tag
                          v-else
                          kind="gray"
                          :label="$t('peers.badge_totp_none')"
                        />
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Device & Protocol -->
                  <cv-data-table-cell>
                    <div class="peer-device-cell">
                      <div class="device-name-line">
                        <Laptop20 class="device-icon" />
                        <strong>{{ peer.device_name }}</strong>
                      </div>
                      <div class="mg-top-xs">
                        <cv-tag
                          kind="blue"
                          :label="$t('peers.protocol_wireguard')"
                        />
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Tunnel IP -->
                  <cv-data-table-cell>
                    <span class="monospace">{{ peer.assigned_ip }}</span>
                  </cv-data-table-cell>

                  <!-- Connection & Handshake -->
                  <cv-data-table-cell>
                    <div class="connection-cell">
                      <div class="connection-indicator">
                        <span
                          class="dot"
                          :class="peer.online ? 'online' : 'offline'"
                        />
                        <span>
                          {{
                            peer.online
                              ? $t("peers.state_online")
                              : peer.last_handshake_at
                              ? $t("peers.state_offline")
                              : $t("peers.never_connected")
                          }}
                        </span>
                      </div>
                      <div
                        v-if="peer.last_handshake_at"
                        class="connection-meta mg-top-xs"
                      >
                        {{
                          $t("peers.last_handshake", {
                            time: formatHandshake(peer.last_handshake_at),
                          })
                        }}
                      </div>
                      <div
                        v-if="peer.last_endpoint"
                        class="connection-meta monospace"
                      >
                        {{
                          $t("peers.endpoint_label", {
                            endpoint: peer.last_endpoint,
                          })
                        }}
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Transfer Volume -->
                  <cv-data-table-cell>
                    <div class="traffic-cell monospace">
                      <div class="rx-line">
                        ↓ {{ formatBytes(peer.rx_bytes) }}
                      </div>
                      <div class="tx-line">
                        ↑ {{ formatBytes(peer.tx_bytes) }}
                      </div>
                    </div>
                  </cv-data-table-cell>

                  <!-- Effective Status -->
                  <cv-data-table-cell>
                    <cv-tag
                      v-if="peer.effective_active"
                      kind="green"
                      :label="$t('peers.status_active')"
                    />
                    <cv-tag
                      v-else-if="!peer.admin_enabled"
                      kind="warm-gray"
                      :label="$t('peers.status_admin_disabled')"
                    />
                    <cv-tag
                      v-else
                      kind="red"
                      :label="$t('peers.status_ad_suspended')"
                    />
                  </cv-data-table-cell>

                  <!-- Row Actions -->
                  <cv-data-table-cell class="actions-cell">
                    <div class="row-actions-group">
                      <cv-icon-button
                        kind="ghost"
                        size="sm"
                        :icon="QrCode20"
                        :label="$t('peers.action_show_qr_conf')"
                        :disabled="loading.peerActionId === peer.id"
                        @click="showPeerQrAndConfig(peer)"
                      />

                      <cv-overflow-menu
                        flip-menu
                        tip-position="left"
                        :aria-label="$t('peers.col_actions')"
                      >
                        <cv-overflow-menu-item
                          @click="showPeerQrAndConfig(peer)"
                        >
                          <NsMenuItem
                            :icon="QrCode20"
                            :label="$t('peers.action_show_qr_conf')"
                          />
                        </cv-overflow-menu-item>

                        <cv-overflow-menu-item
                          v-if="ovpnEnabled"
                          @click="downloadUserOvpn(peer.username)"
                        >
                          <NsMenuItem
                            :icon="Download20"
                            :label="$t('peers.action_download_ovpn')"
                          />
                        </cv-overflow-menu-item>

                        <cv-overflow-menu-item @click="togglePeerState(peer)">
                          <NsMenuItem
                            :icon="peer.admin_enabled ? Locked20 : Unlocked20"
                            :label="
                              peer.admin_enabled
                                ? $t('peers.action_disable_peer')
                                : $t('peers.action_enable_peer')
                            "
                          />
                        </cv-overflow-menu-item>

                        <cv-overflow-menu-item
                          v-if="isUserTotpEnrolled(peer.username)"
                          @click="askResetUserTotp(peer.username)"
                        >
                          <NsMenuItem
                            :icon="Reset20"
                            :label="$t('peers.action_reset_totp')"
                          />
                        </cv-overflow-menu-item>

                        <NsMenuDivider />

                        <cv-overflow-menu-item
                          danger
                          @click="askRevokePeer(peer)"
                        >
                          <NsMenuItem
                            :icon="TrashCan20"
                            :label="$t('peers.action_revoke_peer')"
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

    <!-- Collapsible Section: Synchronized AD/LDAP Users (Provisioning, 2FA Reset & .ovpn Download) -->
    <cv-row v-if="authorizedUsersList.length" class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true">
          <cv-accordion>
            <!-- Authorized Users Without WireGuard Device -->
            <cv-accordion-item
              v-if="authorizedUsersWithoutDevices.length"
              :open="peers.length === 0"
            >
              <template slot="title">
                <strong>
                  {{
                    $t("peers.users_without_devices_title", {
                      count: authorizedUsersWithoutDevices.length,
                    })
                  }}
                </strong>
              </template>
              <template slot="content">
                <p class="helper-paragraph mg-bottom-md">
                  {{ $t("peers.users_without_devices_helper") }}
                </p>
                <div class="unprovisioned-users-grid">
                  <div
                    v-for="user in authorizedUsersWithoutDevices"
                    :key="`nodev-${user.username}`"
                    class="unprovisioned-user-card"
                  >
                    <div class="user-card-meta">
                      <div class="user-card-name">
                        {{ user.display_name || user.username }}
                      </div>
                      <div class="user-card-sub monospace">
                        {{ user.username }}
                      </div>
                      <div class="user-card-email">
                        {{ user.email || $t("peers.user_email_empty") }}
                      </div>
                      <div class="mg-top-xs">
                        <cv-tag
                          v-if="user.totp_enrolled"
                          kind="teal"
                          :label="$t('peers.badge_totp_active')"
                        />
                        <cv-tag
                          v-else
                          kind="gray"
                          :label="$t('peers.badge_totp_none')"
                        />
                      </div>
                    </div>
                    <div class="user-card-actions">
                      <NsButton
                        kind="tertiary"
                        size="sm"
                        :icon="Add20"
                        @click="openCreateModal(user.username)"
                      >
                        {{ $t("peers.create_device_for_user") }}
                      </NsButton>

                      <NsButton
                        v-if="ovpnEnabled"
                        kind="ghost"
                        size="sm"
                        :icon="Download20"
                        :loading="loading.ovpnUsername === user.username"
                        @click="downloadUserOvpn(user.username)"
                      >
                        {{ $t("peers.action_download_ovpn") }}
                      </NsButton>

                      <NsButton
                        v-if="user.totp_enrolled"
                        kind="ghost"
                        size="sm"
                        :icon="Reset20"
                        @click="askResetUserTotp(user.username)"
                      >
                        {{ $t("peers.action_reset_totp") }}
                      </NsButton>
                    </div>
                  </div>
                </div>
              </template>
            </cv-accordion-item>

            <!-- All Authorized Users Directory (2FA Status, Reset & OpenVPN Download) -->
            <cv-accordion-item>
              <template slot="title">
                <strong>
                  {{
                    $t("peers.authorized_users_directory_title", {
                      count: authorizedUsersList.length,
                    })
                  }}
                </strong>
              </template>
              <template slot="content">
                <p class="helper-paragraph mg-bottom-md">
                  {{ $t("peers.authorized_users_directory_helper") }}
                </p>
                <div class="unprovisioned-users-grid">
                  <div
                    v-for="user in authorizedUsersList"
                    :key="`dir-${user.username}`"
                    class="unprovisioned-user-card"
                  >
                    <div class="user-card-meta">
                      <div class="user-card-name">
                        {{ user.display_name || user.username }}
                      </div>
                      <div class="user-card-sub monospace">
                        {{ user.username }} · {{ user.peer_count || 0 }}
                        {{ $t("peers.devices_short") }}
                      </div>
                      <div class="mg-top-xs">
                        <cv-tag
                          v-if="user.totp_enrolled"
                          kind="teal"
                          :label="$t('peers.badge_totp_active')"
                        />
                        <cv-tag
                          v-else
                          kind="gray"
                          :label="$t('peers.badge_totp_none')"
                        />
                      </div>
                    </div>
                    <div class="user-card-actions">
                      <NsButton
                        v-if="ovpnEnabled"
                        kind="ghost"
                        size="sm"
                        :icon="Download20"
                        :loading="loading.ovpnUsername === user.username"
                        @click="downloadUserOvpn(user.username)"
                      >
                        {{ $t("peers.action_download_ovpn") }}
                      </NsButton>

                      <NsButton
                        v-if="user.totp_enrolled"
                        kind="ghost"
                        size="sm"
                        :icon="Reset20"
                        @click="askResetUserTotp(user.username)"
                      >
                        {{ $t("peers.action_reset_totp") }}
                      </NsButton>
                    </div>
                  </div>
                </div>
              </template>
            </cv-accordion-item>
          </cv-accordion>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Create Peer Modal -->
    <NsModal
      size="default"
      :visible="createModal.visible"
      :primaryButtonDisabled="loading.createPeer"
      :isLoading="loading.createPeer"
      @modal-hidden="closeCreateModal"
      @primary-click="submitCreatePeer"
    >
      <template slot="label">{{ $t("peers.create_modal_label") }}</template>
      <template slot="title">{{ $t("peers.create_modal_title") }}</template>
      <template slot="content">
        <cv-form @submit.prevent="submitCreatePeer">
          <NsInlineNotification
            v-if="createModal.errorBanner"
            kind="error"
            :title="$t('error.validation_error')"
            :description="createModal.errorBanner"
            :showCloseButton="false"
            class="mg-bottom-md"
          />

          <NsComboBox
            v-model="createModal.username"
            :title="$t('peers.field_username')"
            :label="$t('peers.field_username_placeholder')"
            :helperText="$t('peers.field_username_helper')"
            :invalidMessage="createModal.errors.username"
            :options="authorizedUserOptions"
            :acceptUserInput="true"
            :autoFilter="true"
            :autoHighlight="true"
            :clearFilterLabel="$t('common.clear_filter')"
            :userInputLabel="$t('common.user_input')"
            showItemDescription
            marginBottomOnOpen
            class="mg-bottom-md"
          />

          <NsTextInput
            v-model.trim="createModal.device_name"
            :label="$t('peers.field_device_name')"
            :placeholder="$t('peers.field_device_name_placeholder')"
            :helperText="$t('peers.field_device_name_helper')"
            :invalidMessage="createModal.errors.device_name"
            ref="deviceNameInput"
            class="mg-bottom-md"
          />

          <NsTextInput
            v-model.trim="newPeerAssignedIp"
            :label="$t('peers.field_assigned_ip')"
            :placeholder="$t('peers.field_assigned_ip_placeholder')"
            :helperText="$t('peers.field_assigned_ip_helper', { network: wgNetwork })"
            :invalidMessage="createModal.errors.assigned_ip"
          />
        </cv-form>
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("peers.create_modal_submit") }}
      </template>
    </NsModal>

    <!-- QR-Code & .conf Download Modal -->
    <NsModal
      size="default"
      :visible="qrModal.visible"
      @modal-hidden="closeQrModal"
      @primary-click="downloadCurrentConf"
    >
      <template slot="label">{{ $t("peers.qr_modal_label") }}</template>
      <template slot="title">
        {{
          $t("peers.qr_modal_title", {
            username: qrModal.username,
            device: qrModal.device_name,
          })
        }}
      </template>
      <template slot="content">
        <NsInlineNotification
          v-if="qrModal.justCreated"
          kind="success"
          :title="$t('peers.qr_modal_created_banner_title')"
          :description="$t('peers.qr_modal_created_banner_description')"
          :showCloseButton="false"
          class="mg-bottom-md"
        />

        <div v-if="loading.getPeerConfig" class="qr-loading-wrap">
          <cv-skeleton-text :paragraph="true" :line-count="6" />
        </div>

        <template v-else>
          <div
            v-if="qrModal.qr_svg_data_uri"
            class="qr-preview-box mg-bottom-md"
          >
            <img
              :src="qrModal.qr_svg_data_uri"
              :alt="$t('peers.qr_scan_hint')"
              class="qr-svg-image"
            />
            <div class="qr-caption">{{ $t("peers.qr_scan_hint") }}</div>
          </div>

          <div class="conf-snippet-wrap">
            <div class="kv-label mg-bottom-xs">
              {{ $t("peers.conf_preview_label") }}
            </div>
            <NsCodeSnippet
              :copyTooltip="$t('common.copy_to_clipboard')"
              :copyFeedback="$t('common.copied')"
              :moreText="$t('common.show_more')"
              :lessText="$t('common.show_less')"
              hideExpandButton
            >
              {{ qrModal.config_text }}
            </NsCodeSnippet>
          </div>
        </template>
      </template>
      <template slot="secondary-button">{{ $t("common.close") }}</template>
      <template slot="primary-button">
        {{ $t("peers.download_conf") }}
      </template>
    </NsModal>

    <!-- Reset User TOTP 2FA Confirmation Modal -->
    <NsModal
      kind="danger"
      size="small"
      :visible="resetTotpModal.visible"
      :primaryButtonDisabled="loading.resetTotp"
      :isLoading="loading.resetTotp"
      @modal-hidden="closeResetTotpModal"
      @primary-click="confirmResetUserTotp"
    >
      <template slot="title">{{ $t("peers.reset_totp_modal_title") }}</template>
      <template slot="content">
        <p class="mg-bottom-sm">
          {{
            $t("peers.reset_totp_modal_question", {
              username: resetTotpModal.username,
            })
          }}
        </p>
        <NsInlineNotification
          kind="warning"
          :description="$t('peers.reset_totp_modal_warning')"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("peers.reset_totp_modal_confirm") }}
      </template>
    </NsModal>

    <!-- Revoke Confirmation Modal -->
    <NsModal
      kind="danger"
      size="small"
      :visible="revokeModal.visible"
      :primaryButtonDisabled="loading.revokePeer"
      :isLoading="loading.revokePeer"
      @modal-hidden="closeRevokeModal"
      @primary-click="confirmRevokePeer"
    >
      <template slot="title">{{ $t("peers.revoke_modal_title") }}</template>
      <template slot="content">
        <p class="mg-bottom-sm">
          {{
            $t("peers.revoke_modal_question", {
              device: revokeModal.peer ? revokeModal.peer.device_name : "",
              ip: revokeModal.peer ? revokeModal.peer.assigned_ip : "",
              username: revokeModal.peer ? revokeModal.peer.username : "",
            })
          }}
        </p>
        <NsInlineNotification
          kind="warning"
          :description="$t('peers.revoke_modal_warning')"
          :showCloseButton="false"
        />
      </template>
      <template slot="secondary-button">{{ $t("common.cancel") }}</template>
      <template slot="primary-button">
        {{ $t("peers.revoke_modal_confirm") }}
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
import QrCode20 from "@carbon/icons-vue/es/qr-code/20";
import Locked20 from "@carbon/icons-vue/es/locked/20";
import Unlocked20 from "@carbon/icons-vue/es/unlocked/20";
import TrashCan20 from "@carbon/icons-vue/es/trash-can/20";
import Laptop20 from "@carbon/icons-vue/es/laptop/20";
import {
  to,
  formatTransferBytes,
  formatRelativeHandshake,
  resolveValidationError,
} from "@/utils/ns8";

const IPV4_ADDRESS_REGEX =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

export default {
  name: "Peers",
  components: {
    Laptop20,
  },
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("peers.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "peers",
      },
      urlCheckInterval: null,
      Renew20,
      QrCode20,
      Locked20,
      Unlocked20,
      TrashCan20,
      ovpnEnabled: false,
      wgNetwork: "10.199.0.0/24",
      newPeerAssignedIp: "",
      users: [],
      peers: [],
      summary: {
        authorized_users: 0,
        total_peers: 0,
        active_peers: 0,
        online_peers: 0,
        max_devices_per_user: 3,
      },
      searchQuery: "",
      statusFilter: "all",
      feedbackBanner: {
        visible: false,
        kind: "success",
        title: "",
        description: "",
      },
      createModal: {
        visible: false,
        username: "",
        device_name: "",
        errorBanner: "",
        errors: {
          username: "",
          device_name: "",
          assigned_ip: "",
        },
      },
      qrModal: {
        visible: false,
        justCreated: false,
        peer_id: "",
        username: "",
        device_name: "",
        config_text: "",
        qr_svg_data_uri: "",
      },
      resetTotpModal: {
        visible: false,
        username: "",
      },
      revokeModal: {
        visible: false,
        peer: null,
      },
      loading: {
        listPeers: false,
        syncUsers: false,
        createPeer: false,
        getPeerConfig: false,
        resetTotp: false,
        ovpnUsername: "",
        revokePeer: false,
        peerActionId: "",
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    tableColumns() {
      return [
        this.$t("peers.col_user"),
        this.$t("peers.col_device"),
        this.$t("peers.col_tunnel_ip"),
        this.$t("peers.col_connection"),
        this.$t("peers.col_traffic"),
        this.$t("peers.col_status"),
        this.$t("peers.col_actions"),
      ];
    },
    usersByUsername() {
      const map = {};
      for (const u of this.users) {
        if (u && u.username) {
          map[u.username.toLowerCase()] = u;
        }
      }
      return map;
    },
    countOnlinePeers() {
      return this.peers.filter((p) => Boolean(p.online)).length;
    },
    countDisabledPeers() {
      return this.peers.filter((p) => !p.admin_enabled).length;
    },
    countUnauthorizedPeers() {
      return this.peers.filter((p) => !p.user_authorized).length;
    },
    filteredPeers() {
      const needle = (this.searchQuery || "").trim().toLowerCase();
      return this.peers.filter((peer) => {
        if (this.statusFilter === "online" && !peer.online) {
          return false;
        }
        if (this.statusFilter === "disabled" && peer.admin_enabled) {
          return false;
        }
        if (this.statusFilter === "unauthorized" && peer.user_authorized) {
          return false;
        }

        if (!needle) {
          return true;
        }

        const haystack = [
          peer.username,
          peer.display_name,
          peer.device_name,
          peer.assigned_ip,
          peer.last_endpoint,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();

        return haystack.includes(needle);
      });
    },
    authorizedUsersList() {
      return this.users.filter((u) => Boolean(u.authorized));
    },
    authorizedUserOptions() {
      return this.authorizedUsersList.map((u) => {
        const displayPart =
          u.display_name && u.display_name !== u.username
            ? `${u.display_name} (${u.username})`
            : u.username;
        const countInfo = `${u.peer_count || 0}/${
          this.summary.max_devices_per_user || 3
        }`;
        return {
          name: u.username,
          label: displayPart,
          value: u.username,
          description: u.email ? `${u.email} · ${countInfo}` : countInfo,
        };
      });
    },
    authorizedUsersWithoutDevices() {
      const usersWithPeers = new Set(this.peers.map((p) => p.username));
      return this.users.filter(
        (u) =>
          Boolean(u.authorized) &&
          (!u.peer_count || u.peer_count === 0) &&
          !usersWithPeers.has(u.username)
      );
    },
  },
  watch: {
    instanceName(newVal, oldVal) {
      if (newVal && newVal !== oldVal) {
        this.loadPeersViewData();
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
      this.loadPeersViewData();
    }
  },
  methods: {
    loadPeersViewData() {
      this.getConfiguration();
      this.listPeers();
    },
    isUserTotpEnrolled(username) {
      if (!username) {
        return false;
      }
      const u = this.usersByUsername[username.toLowerCase()];
      return Boolean(u && u.totp_enrolled);
    },
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
    async getConfiguration() {
      if (!this.core || !this.instanceName) {
        return;
      }
      const taskAction = "get-configuration";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, taskResult) => {
          const cfg = (taskResult && taskResult.output) || {};
          this.ovpnEnabled = Boolean(cfg.ovpn_enabled);
          if (cfg.wg_network) {
            this.wgNetwork = cfg.wg_network;
          }
        }
      );

      await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );
    },
    async listPeers() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.listPeers = true;
      const taskAction = "list-peers";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listPeersAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listPeersCompleted
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
        this.loading.listPeers = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listPeersCompleted(taskContext, taskResult) {
      const out = (taskResult && taskResult.output) || {};
      this.users = Array.isArray(out.users) ? out.users : [];
      this.peers = Array.isArray(out.peers) ? out.peers : [];
      this.summary = {
        ...this.summary,
        ...(out.summary || {}),
      };
      this.loading.listPeers = false;
    },
    listPeersAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listPeers = false;
    },
    async syncUsers() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.syncUsers = true;
      this.feedbackBanner.visible = false;
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
        this.feedbackBanner = {
          visible: true,
          kind: "error",
          title: this.$t("status.sync_error_title"),
          description: out.message || this.$t("status.sync_status_ldap_error"),
        };
      } else {
        this.feedbackBanner = {
          visible: true,
          kind: "success",
          title: this.$t("status.sync_success_title"),
          description: this.$t("peers.sync_completed_banner", {
            authorized: out.authorized_users || 0,
            active: out.active_peers || 0,
            suspended: out.suspended_peers || 0,
          }),
        };
      }
      this.listPeers();
    },
    syncUsersAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.syncUsers = false;
    },
    openCreateModal(preselectedUsername = "") {
      this.newPeerAssignedIp = "";
      this.createModal = {
        visible: true,
        username: preselectedUsername || "",
        device_name: "",
        errorBanner: "",
        errors: {
          username: "",
          device_name: "",
          assigned_ip: "",
        },
      };
    },
    closeCreateModal() {
      this.createModal.visible = false;
    },
    validateCreatePeerForm() {
      this.createModal.errorBanner = "";
      this.createModal.errors.username = "";
      this.createModal.errors.device_name = "";
      this.createModal.errors.assigned_ip = "";
      let valid = true;

      if (!this.createModal.username || !this.createModal.username.trim()) {
        this.createModal.errors.username = this.$t(
          "peers.validation_username_required"
        );
        valid = false;
      }

      const devName = (this.createModal.device_name || "").trim();
      if (!devName) {
        this.createModal.errors.device_name = this.$t(
          "peers.validation_device_name_required"
        );
        valid = false;
      } else if (
        devName.length > 64 ||
        !/^[A-Za-z0-9ÄÖÜäöüß _.-]+$/.test(devName)
      ) {
        this.createModal.errors.device_name = this.$t(
          "peers.validation_device_name_invalid"
        );
        valid = false;
      }

      const staticIp = (this.newPeerAssignedIp || "").trim();
      if (staticIp && !IPV4_ADDRESS_REGEX.test(staticIp)) {
        this.createModal.errors.assigned_ip = this.$t(
          "peers.validation_assigned_ip_invalid"
        );
        valid = false;
      }

      return valid;
    },
    async submitCreatePeer() {
      if (!this.validateCreatePeerForm()) {
        return;
      }
      if (!this.core || !this.instanceName) {
        return;
      }

      this.loading.createPeer = true;
      const taskAction = "create-peer";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.createPeerAborted
      );
      this.core.$root.$once(
        `${taskAction}-validation-failed-${eventId}`,
        this.createPeerValidationFailed
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.createPeerCompleted
      );

      const payload = {
        username: this.createModal.username.trim(),
        device_name: this.createModal.device_name.trim(),
      };
      const staticIp = (this.newPeerAssignedIp || "").trim();
      if (staticIp) {
        payload.assigned_ip = staticIp;
      }

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
        this.loading.createPeer = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    createPeerValidationFailed(validationErrors) {
      this.loading.createPeer = false;
      const list = Array.isArray(validationErrors)
        ? validationErrors
        : validationErrors && Array.isArray(validationErrors.output)
        ? validationErrors.output
        : [];

      for (const item of list) {
        const param = item.parameter || item.field;
        const msg = resolveValidationError(this, "peers", item);
        if (
          param &&
          Object.prototype.hasOwnProperty.call(this.createModal.errors, param)
        ) {
          this.createModal.errors[param] = msg;
        } else {
          this.createModal.errorBanner = msg;
        }
      }
    },
    createPeerCompleted(taskContext, taskResult) {
      this.loading.createPeer = false;
      const out = (taskResult && taskResult.output) || {};
      const createdPeer = out.peer || {};

      const username = createdPeer.username || this.createModal.username;
      const deviceName =
        createdPeer.device_name || this.createModal.device_name;

      this.createModal.visible = false;

      // Transition directly into QR-Code + .conf download modal
      this.qrModal = {
        visible: true,
        justCreated: true,
        peer_id: createdPeer.id || "",
        username,
        device_name: deviceName,
        config_text: out.config_text || "",
        qr_svg_data_uri: out.qr_svg_data_uri || "",
      };

      this.listPeers();
    },
    createPeerAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.createPeer = false;

      const rawErr = String(
        (taskResult && (taskResult.error || taskResult.output)) || ""
      );
      const staticIp = (this.newPeerAssignedIp || "").trim();

      if (/HTTP\s+409\b|already assigned/i.test(rawErr)) {
        if (staticIp) {
          const msg = this.$t("peers.error_ip_already_assigned", {
            ip: staticIp,
          });
          this.createModal.errors.assigned_ip = msg;
          this.createModal.errorBanner = msg;
        } else {
          this.createModal.errorBanner = this.$t(
            "peers.error_ip_pool_exhausted",
            { network: this.wgNetwork }
          );
        }
        return;
      }

      if (/HTTP\s+400\b/i.test(rawErr) && staticIp) {
        if (
          /ip|network|subnet|address|server|broadcast|outside|reserved/i.test(
            rawErr
          )
        ) {
          const msg = this.$t("peers.error_ip_outside_network", {
            ip: staticIp,
            network: this.wgNetwork,
          });
          this.createModal.errors.assigned_ip = msg;
          this.createModal.errorBanner = msg;
          return;
        }
      }

      if (/HTTP\s+403\b|not in authorized|does not exist/i.test(rawErr)) {
        this.createModal.errorBanner = this.$t("error.user_not_authorized");
        return;
      }

      if (/max_devices_per_user/i.test(rawErr)) {
        this.createModal.errorBanner = this.$t("error.device_limit_reached");
        return;
      }

      this.createModal.errorBanner = this.$t("error.generic_error");
    },
    async showPeerQrAndConfig(peer) {
      if (!this.core || !this.instanceName || !peer) {
        return;
      }

      this.qrModal = {
        visible: true,
        justCreated: false,
        peer_id: peer.id,
        username: peer.username,
        device_name: peer.device_name,
        config_text: "",
        qr_svg_data_uri: "",
      };
      this.loading.getPeerConfig = true;

      const taskAction = "get-peer-config";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getPeerConfigAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getPeerConfigCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            peer_id: peer.id,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.getPeerConfig = false;
        this.qrModal.visible = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getPeerConfigCompleted(taskContext, taskResult) {
      this.loading.getPeerConfig = false;
      const out = (taskResult && taskResult.output) || {};
      this.qrModal.config_text = out.config_text || "";
      this.qrModal.qr_svg_data_uri = out.qr_svg_data_uri || "";
      if (out.username) {
        this.qrModal.username = out.username;
      }
      if (out.device_name) {
        this.qrModal.device_name = out.device_name;
      }
    },
    getPeerConfigAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.getPeerConfig = false;
      this.qrModal.visible = false;
    },
    closeQrModal() {
      this.qrModal.visible = false;
    },
    downloadCurrentConf() {
      if (!this.qrModal.config_text) {
        return;
      }
      const safeUser = (this.qrModal.username || "vpn")
        .replace(/[^A-Za-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "");
      const safeDevice = (this.qrModal.device_name || "device")
        .replace(/[^A-Za-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "");
      const filename = `${safeUser || "vpn"}-${safeDevice || "device"}.conf`;

      this.triggerBlobDownload(filename, this.qrModal.config_text);
    },
    triggerBlobDownload(filename, textContent) {
      const blob = new Blob([textContent], {
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
    async downloadUserOvpn(username) {
      if (!this.core || !this.instanceName || !username) {
        return;
      }
      this.loading.ovpnUsername = username;
      this.feedbackBanner.visible = false;
      const taskAction = "get-user-ovpn";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.ovpnUsername = "";
      });
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        (ctx, taskResult) => {
          this.loading.ovpnUsername = "";
          const out = (taskResult && taskResult.output) || {};
          if (!out.ovpn_text) {
            return;
          }
          const safeUser = username
            .replace(/[^A-Za-z0-9._-]+/g, "-")
            .replace(/^-+|-+$/g, "");
          const filename = out.filename || `${safeUser || "vpn"}.ovpn`;
          this.triggerBlobDownload(filename, out.ovpn_text);

          this.feedbackBanner = {
            visible: true,
            kind: "info",
            title: this.$t("peers.ovpn_downloaded_title", { username }),
            description: out.totp_required_on_connect
              ? this.$t("peers.ovpn_downloaded_totp_hint")
              : this.$t("peers.ovpn_downloaded_ad_hint"),
          };
        }
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            username,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.ovpnUsername = "";
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    askResetUserTotp(username) {
      if (!username) {
        return;
      }
      this.resetTotpModal = {
        visible: true,
        username,
      };
    },
    closeResetTotpModal() {
      this.resetTotpModal.visible = false;
      this.resetTotpModal.username = "";
    },
    async confirmResetUserTotp() {
      const targetUsername = this.resetTotpModal.username;
      if (!this.core || !this.instanceName || !targetUsername) {
        return;
      }

      this.loading.resetTotp = true;
      this.feedbackBanner.visible = false;
      const taskAction = "reset-user-totp";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.resetTotp = false;
      });
      this.core.$root.$once(`${taskAction}-completed-${eventId}`, () => {
        this.loading.resetTotp = false;
        this.resetTotpModal.visible = false;
        this.resetTotpModal.username = "";
        this.feedbackBanner = {
          visible: true,
          kind: "success",
          title: this.$t("peers.reset_totp_modal_title"),
          description: this.$t("peers.reset_totp_success_banner", {
            username: targetUsername,
          }),
        };
        this.listPeers();
      });

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            username: targetUsername,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.resetTotp = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    async togglePeerState(peer) {
      if (!this.core || !this.instanceName || !peer) {
        return;
      }

      this.loading.peerActionId = peer.id;
      this.feedbackBanner.visible = false;
      const desiredEnabled = !peer.admin_enabled;
      const taskAction = "toggle-peer";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.peerActionId = "";
      });
      this.core.$root.$once(`${taskAction}-completed-${eventId}`, () => {
        this.loading.peerActionId = "";
        this.feedbackBanner = {
          visible: true,
          kind: desiredEnabled ? "success" : "info",
          title: desiredEnabled
            ? this.$t("peers.action_enable_peer")
            : this.$t("peers.action_disable_peer"),
          description: desiredEnabled
            ? this.$t("peers.toggle_enabled_banner", {
                device: peer.device_name,
                username: peer.username,
              })
            : this.$t("peers.toggle_disabled_banner", {
                device: peer.device_name,
                username: peer.username,
              }),
        };
        this.listPeers();
      });

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            peer_id: peer.id,
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
        this.loading.peerActionId = "";
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    askRevokePeer(peer) {
      this.revokeModal = {
        visible: true,
        peer,
      };
    },
    closeRevokeModal() {
      this.revokeModal.visible = false;
      this.revokeModal.peer = null;
    },
    async confirmRevokePeer() {
      const targetPeer = this.revokeModal.peer;
      if (!this.core || !this.instanceName || !targetPeer) {
        return;
      }

      this.loading.revokePeer = true;
      this.feedbackBanner.visible = false;
      const taskAction = "revoke-peer";
      const eventId = this.getUuid();

      this.core.$root.$once(`${taskAction}-aborted-${eventId}`, (res, ctx) => {
        console.error(`${ctx.action} aborted`, res);
        this.loading.revokePeer = false;
      });
      this.core.$root.$once(`${taskAction}-completed-${eventId}`, () => {
        this.loading.revokePeer = false;
        this.revokeModal.visible = false;
        this.revokeModal.peer = null;
        this.feedbackBanner = {
          visible: true,
          kind: "success",
          title: this.$t("peers.revoke_modal_title"),
          description: this.$t("peers.revoked_banner", {
            device: targetPeer.device_name,
            username: targetPeer.username,
          }),
        };
        this.listPeers();
      });

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            peer_id: targetPeer.id,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.revokePeer = false;
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

.peers-toolbar-tile {
  padding: 1rem;
}

.peers-toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;

  .toolbar-filters {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.75rem;
    flex: 1;
    min-width: 18rem;

    .search-wrap {
      flex: 1;
      min-width: 15rem;
      max-width: 26rem;
    }

    .status-filter-wrap {
      min-width: 13.5rem;
    }
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

.peer-user-cell {
  .peer-user-primary {
    font-weight: 600;
  }

  .peer-user-sub {
    font-size: 0.75rem;
    color: #525252;
  }

  .user-badges-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.25rem;
  }
}

.peer-device-cell {
  .device-name-line {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;

    .device-icon {
      fill: #525252;
      flex-shrink: 0;
    }
  }
}

.connection-cell {
  .connection-meta {
    font-size: 0.75rem;
    color: #525252;
  }
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

.helper-paragraph {
  color: #525252;
  font-size: 0.875rem;
}

.unprovisioned-users-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr));
  gap: 0.75rem;
}

.unprovisioned-user-card {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  background-color: #f8f9fb;
  border: 1px solid #e0e0e0;

  .user-card-name {
    font-weight: 600;
  }

  .user-card-sub,
  .user-card-email {
    font-size: 0.75rem;
    color: #525252;
  }

  .user-card-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
  }
}

.qr-preview-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: #ffffff;
  border: 1px solid #e0e0e0;
  padding: 1rem;

  .qr-svg-image {
    width: 14rem;
    height: 14rem;
    object-fit: contain;
  }

  .qr-caption {
    margin-top: 0.5rem;
    font-size: 0.8125rem;
    color: #525252;
  }
}
</style>
