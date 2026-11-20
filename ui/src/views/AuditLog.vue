<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <div class="page-header-row">
          <div>
            <h2>{{ $t("audit.title") }}</h2>
            <p class="page-subtitle">{{ $t("audit.subtitle") }}</p>
          </div>
          <div v-if="totalCount > 0" class="audit-total-badge">
            <NsTag
              kind="cool-gray"
              :label="
                $t('audit.loaded_summary', {
                  shown: filteredEntries.length,
                  total: totalCount,
                })
              "
            />
          </div>
        </div>
      </cv-column>
    </cv-row>

    <!-- Toolbar: Search, Actions & Category Filter Pills -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true" class="audit-toolbar-tile">
          <div class="audit-toolbar-top">
            <div class="search-wrap">
              <cv-search
                v-model="searchQuery"
                :label="$t('common.search')"
                :placeholder="$t('audit.search_placeholder')"
                :clear-aria-label="$t('common.clear_filter')"
                size="xl"
              />
            </div>

            <div class="toolbar-actions">
              <NsButton
                kind="secondary"
                size="field"
                :icon="Renew20"
                :loading="loading.listLogs"
                :disabled="loading.listLogs"
                @click="listAuditLogs"
              >
                {{ $t("audit.refresh") }}
              </NsButton>

              <NsButton
                kind="primary"
                size="field"
                :icon="Download20"
                :disabled="!filteredEntries.length || loading.listLogs"
                @click="exportCsv"
              >
                {{ $t("audit.export_csv") }}
              </NsButton>
            </div>
          </div>

          <div
            class="category-pills-row mg-top-sm"
            role="group"
            :aria-label="$t('audit.filter_category_label')"
          >
            <NsTag
              v-for="cat in categoryOptions"
              :key="cat.id"
              :kind="categoryFilter === cat.id ? 'blue' : 'cool-gray'"
              :label="cat.label"
              :class="[
                'category-pill',
                { 'category-pill--active': categoryFilter === cat.id },
              ]"
              @click="selectCategory(cat.id)"
            />
          </div>
        </cv-tile>
      </cv-column>
    </cv-row>

    <!-- Audit Log Data Table -->
    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true">
          <cv-data-table-skeleton
            v-if="loading.listLogs"
            :columns="tableColumns"
            :rows="6"
          />

          <NsEmptyState
            v-else-if="!entries.length"
            :title="$t('audit.empty_title')"
          >
            <template #pictogram>
              <DocumentSecurityPictogram />
            </template>
            <template #description>
              <div>{{ $t("audit.empty_description") }}</div>
            </template>
          </NsEmptyState>

          <NsEmptyState
            v-else-if="!filteredEntries.length"
            :title="$t('audit.no_results_title')"
          >
            <template #description>
              <div>{{ $t("audit.no_results_description") }}</div>
            </template>
          </NsEmptyState>

          <template v-else>
            <div class="responsive-table-wrapper">
              <cv-data-table :columns="tableColumns">
                <template slot="data">
                  <cv-data-table-row
                    v-for="entry in paginatedEntries"
                    :key="`audit-${entry.id}`"
                    :value="String(entry.id)"
                  >
                    <!-- Timestamp -->
                    <cv-data-table-cell class="timestamp-cell">
                      <div class="timestamp-primary" :title="entry.timestamp">
                        {{ formatAuditTimestamp(entry.timestamp) }}
                      </div>
                      <div class="timestamp-iso monospace">
                        {{ entry.timestamp || "-" }}
                      </div>
                    </cv-data-table-cell>

                    <!-- Event Type Badge -->
                    <cv-data-table-cell class="event-cell">
                      <div>
                        <NsTag
                          :kind="eventBadgeKind(entry.event_type)"
                          :label="eventBadgeLabel(entry.event_type)"
                        />
                      </div>
                      <div class="event-code monospace mg-top-xs">
                        {{ entry.event_type }}
                      </div>
                    </cv-data-table-cell>

                    <!-- Actor Badge -->
                    <cv-data-table-cell class="actor-cell">
                      <NsTag
                        :kind="actorBadgeKind(entry.actor)"
                        :label="actorBadgeLabel(entry.actor)"
                      />
                    </cv-data-table-cell>

                    <!-- User / Target ID -->
                    <cv-data-table-cell class="target-cell">
                      <div v-if="entry.username" class="target-username">
                        {{ entry.username }}
                      </div>
                      <div
                        v-if="entry.peer_id"
                        class="target-peer-id monospace"
                        :title="entry.peer_id"
                      >
                        {{ shortenTargetId(entry.peer_id) }}
                      </div>
                      <span
                        v-if="!entry.username && !entry.peer_id"
                        class="muted-dash"
                      >
                        -
                      </span>
                    </cv-data-table-cell>

                    <!-- Details -->
                    <cv-data-table-cell class="details-cell">
                      <div class="details-text">
                        {{ entry.details || "-" }}
                      </div>
                    </cv-data-table-cell>
                  </cv-data-table-row>
                </template>
              </cv-data-table>
            </div>

            <NsPagination
              v-if="filteredEntries.length > pagination.pageSizes[0]"
              :numberOfItems="filteredEntries.length"
              :pageSizes="pagination.pageSizes"
              :page="pagination.page"
              :backwardText="$t('common.previous_page')"
              :forwardText="$t('common.next_page')"
              :pageNumberLabel="$t('common.page_number')"
              :pageSizesLabel="$t('common.items_per_page')"
              :rangeOfTotalItemsLabel="$t('common.range_of_total_items')"
              :ofTotalPagesLabel="$t('common.of_total_pages')"
              @change="onPaginationChange"
            />
          </template>
        </cv-tile>
      </cv-column>
    </cv-row>
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
import Download20 from "@carbon/icons-vue/es/download/20";
import { to } from "@/utils/ns8";

const SECURITY_EVENTS = new Set([
  "portal_login_failed",
  "portal_totp_failed",
  "portal_login_ok",
  "openvpn_auth_denied",
  "openvpn_auth_ok",
  "peer_auto_suspended",
  "peer_revoked",
]);

const PEER_EVENTS = new Set([
  "peer_created",
  "peer_toggled",
  "peer_revoked",
  "totp_enrolled",
  "totp_reset",
]);

const SYNC_EVENTS = new Set([
  "peer_auto_suspended",
  "peer_auto_restored",
  "ldap_sync",
  "sync_completed",
  "sync_error",
]);

const CONFIG_EVENTS = new Set([
  "config_updated",
  "s2s_created",
  "s2s_toggled",
  "s2s_deleted",
]);

const EVENT_BADGE_KINDS = {
  portal_login_failed: "red",
  portal_totp_failed: "red",
  openvpn_auth_denied: "red",
  peer_revoked: "red",
  peer_auto_suspended: "magenta",
  totp_reset: "warm-gray",
  s2s_deleted: "warm-gray",
  peer_created: "green",
  portal_login_ok: "green",
  openvpn_auth_ok: "green",
  totp_enrolled: "teal",
  peer_auto_restored: "teal",
  peer_toggled: "blue",
  s2s_toggled: "blue",
  s2s_created: "cyan",
  config_updated: "purple",
};

const ACTOR_BADGE_KINDS = {
  admin: "purple",
  portal: "cyan",
  ldap_sync: "teal",
  openvpn: "blue",
  system: "cool-gray",
};

export default {
  name: "AuditLog",
  mixins: [
    TaskService,
    IconService,
    UtilService,
    QueryParamService,
    PageTitleService,
  ],
  pageTitle() {
    return this.$t("audit.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "audit-log",
      },
      urlCheckInterval: null,
      Renew20,
      Download20,
      entries: [],
      totalCount: 0,
      searchQuery: "",
      categoryFilter: "all",
      pagination: {
        page: 1,
        start: 1,
        length: 25,
        pageSizes: [25, 50, 100, 250],
      },
      loading: {
        listLogs: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    tableColumns() {
      return [
        this.$t("audit.col_timestamp"),
        this.$t("audit.col_event"),
        this.$t("audit.col_actor"),
        this.$t("audit.col_user_target"),
        this.$t("audit.col_details"),
      ];
    },
    categoryOptions() {
      const categories = ["all", "security", "peers", "sync", "config"];
      return categories.map((catId) => {
        const count =
          catId === "all"
            ? this.entries.length
            : this.entries.filter((e) => this.matchesCategory(e, catId)).length;
        return {
          id: catId,
          count,
          label: this.$t(`audit.category_${catId}`, { count }),
        };
      });
    },
    filteredEntries() {
      const needle = (this.searchQuery || "").trim().toLowerCase();
      return this.entries.filter((entry) => {
        if (!this.matchesCategory(entry, this.categoryFilter)) {
          return false;
        }
        if (!needle) {
          return true;
        }
        const haystack = [
          entry.username,
          entry.details,
          entry.event_type,
          this.eventBadgeLabel(entry.event_type),
          entry.actor,
          this.actorBadgeLabel(entry.actor),
          entry.peer_id,
          entry.timestamp,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(needle);
      });
    },
    paginatedEntries() {
      const startIdx = Math.max(0, (this.pagination.start || 1) - 1);
      const len = this.pagination.length || 25;
      return this.filteredEntries.slice(startIdx, startIdx + len);
    },
  },
  watch: {
    instanceName(newVal, oldVal) {
      if (newVal && newVal !== oldVal) {
        this.listAuditLogs();
      }
    },
    searchQuery() {
      this.resetPagination();
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
      this.listAuditLogs();
    }
  },
  methods: {
    selectCategory(catId) {
      this.categoryFilter = catId;
      this.resetPagination();
    },
    resetPagination() {
      this.pagination.page = 1;
      this.pagination.start = 1;
    },
    onPaginationChange(ev) {
      if (!ev) {
        return;
      }
      this.pagination.start = ev.start || 1;
      this.pagination.page = ev.page || 1;
      this.pagination.length = ev.length || 25;
    },
    matchesCategory(entry, category) {
      if (!category || category === "all") {
        return true;
      }
      const ev = String((entry && entry.event_type) || "").toLowerCase();
      const actor = String((entry && entry.actor) || "").toLowerCase();

      if (category === "security") {
        return (
          SECURITY_EVENTS.has(ev) ||
          /login|auth|denied|fail|revok|suspend/i.test(ev)
        );
      }
      if (category === "peers") {
        return PEER_EVENTS.has(ev) || /^(peer_|totp_)/i.test(ev);
      }
      if (category === "sync") {
        return (
          actor === "ldap_sync" ||
          SYNC_EVENTS.has(ev) ||
          /ldap|sync|auto_suspend|auto_restor/i.test(ev)
        );
      }
      if (category === "config") {
        return CONFIG_EVENTS.has(ev) || /^(config_|s2s_)/i.test(ev);
      }
      return true;
    },
    eventBadgeKind(eventType) {
      const key = String(eventType || "").toLowerCase();
      if (EVENT_BADGE_KINDS[key]) {
        return EVENT_BADGE_KINDS[key];
      }
      if (/fail|denied|error|revok/i.test(key)) {
        return "red";
      }
      if (/suspend/i.test(key)) {
        return "magenta";
      }
      if (/creat|ok|enrol|restor/i.test(key)) {
        return "green";
      }
      return "cool-gray";
    },
    eventBadgeLabel(eventType) {
      const raw = String(eventType || "").trim();
      if (!raw) {
        return "-";
      }
      const i18nKey = `audit.event_${raw}`;
      if (this.$te(i18nKey)) {
        return this.$t(i18nKey);
      }
      return raw.replace(/_/g, " ");
    },
    actorBadgeKind(actor) {
      const key = String(actor || "").toLowerCase();
      return ACTOR_BADGE_KINDS[key] || "gray";
    },
    actorBadgeLabel(actor) {
      const raw = String(actor || "system").trim();
      const i18nKey = `audit.actor_${raw.toLowerCase()}`;
      if (this.$te(i18nKey)) {
        return this.$t(i18nKey);
      }
      return raw;
    },
    shortenTargetId(peerId) {
      const raw = String(peerId || "").trim();
      if (raw.length <= 14) {
        return raw;
      }
      return `${raw.slice(0, 8)}…${raw.slice(-4)}`;
    },
    formatAuditTimestamp(isoValue) {
      if (!isoValue) {
        return "-";
      }
      const dateObj = new Date(isoValue);
      if (Number.isNaN(dateObj.getTime())) {
        return String(isoValue);
      }
      try {
        return new Intl.DateTimeFormat(this.$i18n.locale || "en", {
          dateStyle: "medium",
          timeStyle: "medium",
        }).format(dateObj);
      } catch (err) {
        return dateObj.toLocaleString();
      }
    },
    async listAuditLogs() {
      if (!this.core || !this.instanceName) {
        return;
      }
      this.loading.listLogs = true;
      const taskAction = "list-audit-logs";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.listAuditLogsAborted
      );
      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.listAuditLogsCompleted
      );

      const [err] = await to(
        this.createModuleTaskForApp(this.instanceName, {
          action: taskAction,
          data: {
            limit: 250,
          },
          extra: {
            title: this.$t("action." + taskAction),
            isNotificationHidden: true,
            eventId,
          },
        })
      );

      if (err) {
        this.loading.listLogs = false;
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    listAuditLogsCompleted(taskContext, taskResult) {
      const out = (taskResult && taskResult.output) || {};
      this.entries = Array.isArray(out.entries) ? out.entries : [];
      this.totalCount =
        typeof out.total === "number" ? out.total : this.entries.length;
      this.loading.listLogs = false;
    },
    listAuditLogsAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
      this.loading.listLogs = false;
    },
    escapeCsvField(value) {
      if (value === null || value === undefined) {
        return "";
      }
      const str = String(value);
      if (/[",\r\n]/.test(str)) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    },
    exportCsv() {
      if (!this.filteredEntries.length) {
        return;
      }
      const headers = [
        "id",
        "timestamp",
        "event_type",
        "event_label",
        "actor",
        "username",
        "peer_id",
        "details",
      ];
      const rows = [headers.join(",")];

      for (const item of this.filteredEntries) {
        const record = [
          item.id,
          item.timestamp || "",
          item.event_type || "",
          this.eventBadgeLabel(item.event_type),
          item.actor || "",
          item.username || "",
          item.peer_id || "",
          item.details || "",
        ].map((cell) => this.escapeCsvField(cell));
        rows.push(record.join(","));
      }

      // RFC-4180 CRLF row endings + UTF-8 BOM for direct Excel / LibreOffice DSGVO audit import
      const csvContent = "\uFEFF" + rows.join("\r\n") + "\r\n";
      const blob = new Blob([csvContent], {
        type: "text/csv;charset=utf-8;",
      });

      const safeInstance = (this.instanceName || "vpn")
        .replace(/[^A-Za-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "");
      const dateStamp = new Date().toISOString().slice(0, 10);
      const filename = `${safeInstance || "vpn"}-audit-log-${dateStamp}.csv`;

      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    },
  },
};
</script>

<style scoped lang="scss">
.page-title {
  margin-top: 1.5rem;
}

.audit-total-badge {
  display: flex;
  align-items: center;
  padding-top: 0.25rem;
}

.audit-toolbar-tile {
  padding: 1rem;
}

.audit-toolbar-top {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.search-wrap {
  flex: 1 1 20rem;
  max-width: 34rem;
}

.toolbar-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.75rem;
}

.category-pills-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.35rem;
  padding-top: 0.5rem;
  border-top: 1px solid #e0e0e0;

  .category-pill {
    margin: 0.15rem 0;
    cursor: pointer;

    &.category-pill--active {
      font-weight: 600;
      box-shadow: 0 0 0 1px #0f62fe;
    }
  }
}

.responsive-table-wrapper {
  width: 100%;
  overflow-x: auto;
}

.timestamp-cell {
  white-space: nowrap;

  .timestamp-primary {
    font-weight: 500;
    color: #161616;
  }

  .timestamp-iso {
    font-size: 0.75rem;
    color: #6f6f6f;
    margin-top: 0.15rem;
  }
}

.event-cell {
  white-space: nowrap;

  .event-code {
    font-size: 0.75rem;
    color: #6f6f6f;
  }
}

.actor-cell {
  white-space: nowrap;
}

.target-cell {
  .target-username {
    font-weight: 600;
    color: #161616;
  }

  .target-peer-id {
    font-size: 0.75rem;
    color: #525252;
    margin-top: 0.15rem;
  }

  .muted-dash {
    color: #8d8d8d;
  }
}

.details-cell {
  min-width: 18rem;

  .details-text {
    color: #161616;
    line-height: 1.45;
    word-break: break-word;
  }
}
</style>
