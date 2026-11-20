<template>
  <div id="app" class="ns8-app-shell">
    <AppSideMenu />
    <AppMobileSideMenu
      :isShown="isMobileSideMenuShown"
      @close="isMobileSideMenuShown = false"
    />

    <div class="app-content">
      <header class="ns8-instance-header">
        <div class="instance-title-group">
          <cv-icon-button
            class="mobile-menu-btn"
            kind="ghost"
            size="sm"
            :icon="Menu20"
            label="Menu"
            @click="isMobileSideMenuShown = !isMobileSideMenuShown"
          />
          <Vpn20 />
          <span class="instance-badge">
            {{ instanceLabel || instanceName || appName }}
          </span>
          <span v-if="instanceLabel && instanceName" class="instance-id-sub">
            ({{ instanceName }})
          </span>
        </div>

        <div
          class="ns8-lang-switch"
          role="group"
          :aria-label="$t('common.lang_switch_label')"
        >
          <button
            type="button"
            class="ns8-lang-btn"
            :class="{ 'is-active': currentLocale === 'en' }"
            :aria-pressed="currentLocale === 'en' ? 'true' : 'false'"
            @click="switchUiLocale('en')"
          >
            EN
          </button>
          <span class="ns8-lang-sep" aria-hidden="true">|</span>
          <button
            type="button"
            class="ns8-lang-btn"
            :class="{ 'is-active': currentLocale === 'de' }"
            :aria-pressed="currentLocale === 'de' ? 'true' : 'false'"
            @click="switchUiLocale('de')"
          >
            DE
          </button>
        </div>
      </header>

      <router-view />
    </div>
  </div>
</template>

<script>
import { mapState, mapActions } from "vuex";
import {
  QueryParamService,
  TaskService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import Menu20 from "@carbon/icons-vue/es/menu/20";
import Vpn20 from "@carbon/icons-vue/es/VPN/20";
import AppSideMenu from "./components/AppSideMenu.vue";
import AppMobileSideMenu from "./components/AppMobileSideMenu.vue";
import { loadLanguageAsync } from "./i18n";
import { getParentCore, to } from "./utils/ns8";

export default {
  name: "App",
  components: {
    AppSideMenu,
    AppMobileSideMenu,
    Vpn20,
  },
  mixins: [QueryParamService, TaskService, UtilService],
  data() {
    return {
      isMobileSideMenuShown: false,
      Menu20,
    };
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core", "appName"]),
    currentLocale() {
      return (this.$i18n && this.$i18n.locale) || "en";
    },
  },
  async created() {
    const core = getParentCore();
    if (core) {
      this.setCoreInStore(core);
    }

    // Listen to custom route change events dispatched by QueryParamService
    this.onChangeRoute = (e) => {
      const requestedPage = e.detail || "status";
      const targetPath = requestedPage.startsWith("/")
        ? requestedPage
        : `/${requestedPage}`;
      if (this.$route.path !== targetPath) {
        this.$router.replace(targetPath).catch(() => {});
      }
    };
    window.addEventListener("changeRoute", this.onChangeRoute);

    // Extract instanceName from parent NS8 Cluster-Admin hash (#/apps/vpn1?page=...)
    let detectedInstance = "";
    try {
      if (window.parent && window.parent.location && window.parent.location.hash) {
        const match = /#\/apps\/([a-zA-Z0-9_-]+)/.exec(
          window.parent.location.hash
        );
        if (match && match[1]) {
          detectedInstance = match[1];
        }
      }
    } catch (err) {
      // Standalone mode fallback
    }

    if (detectedInstance) {
      this.setInstanceNameInStore(detectedInstance);
    }

    // Default to English ("en") unless the administrator explicitly selected another language
    let preferredLocale = "en";
    try {
      const savedLang = localStorage.getItem("ns8_vpnportal_lang");
      if (savedLang === "en" || savedLang === "de") {
        preferredLocale = savedLang;
      }
    } catch (err) {
      // Ignore storage restrictions
    }
    await loadLanguageAsync(this.$i18n, preferredLocale);

    // Sync initial page from NS8 query parameter if running in Cockpit
    if (core) {
      const initialPage = this.getPage();
      if (initialPage && this.$route.path !== `/${initialPage}`) {
        this.$router.replace(`/${initialPage}`).catch(() => {});
      }

      core.$root.$on("changeLocale", this.onCoreLocaleChange);
    }

    if (core && detectedInstance) {
      this.retrieveInstanceLabel();
    }
  },
  beforeDestroy() {
    if (this.onChangeRoute) {
      window.removeEventListener("changeRoute", this.onChangeRoute);
    }
    if (this.core && this.core.$root) {
      this.core.$root.$off("changeLocale", this.onCoreLocaleChange);
    }
  },
  methods: {
    ...mapActions([
      "setInstanceNameInStore",
      "setInstanceLabelInStore",
      "setCoreInStore",
    ]),
    async switchUiLocale(newLocale) {
      const target = newLocale === "de" ? "de" : "en";
      try {
        localStorage.setItem("ns8_vpnportal_lang", target);
      } catch (err) {
        // Ignore storage restrictions
      }
      await loadLanguageAsync(this.$i18n, target);
    },
    async onCoreLocaleChange(newLocale) {
      await this.switchUiLocale(newLocale);
    },
    async retrieveInstanceLabel() {
      if (!this.core || !this.instanceName) {
        return;
      }
      const taskAction = "get-name";
      const eventId = this.getUuid();

      this.core.$root.$once(
        `${taskAction}-completed-${eventId}`,
        this.getNameCompleted
      );
      this.core.$root.$once(
        `${taskAction}-aborted-${eventId}`,
        this.getNameAborted
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
        this.createErrorNotificationForApp(
          err,
          this.$t("task.cannot_create_task", { action: taskAction })
        );
      }
    },
    getNameCompleted(taskContext, taskResult) {
      if (taskResult && taskResult.output && taskResult.output.name) {
        this.setInstanceLabelInStore(taskResult.output.name);
      }
    },
    getNameAborted(taskResult, taskContext) {
      console.error(`${taskContext.action} aborted`, taskResult);
    },
  },
};
</script>

<style lang="scss">
@import "./styles/core";
</style>
