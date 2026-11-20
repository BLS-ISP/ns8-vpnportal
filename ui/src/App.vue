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

    // Sync locale from NS8 core or browser settings
    let preferredLocale = navigator.language || "en";
    if (core && core.$root && core.$root.$i18n && core.$root.$i18n.locale) {
      preferredLocale = core.$root.$i18n.locale;
    } else {
      try {
        const storedLang = localStorage.getItem("lang");
        if (storedLang) {
          preferredLocale = JSON.parse(storedLang);
        }
      } catch (err) {
        // Ignore invalid storage entry
      }
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
    async onCoreLocaleChange(newLocale) {
      await loadLanguageAsync(this.$i18n, newLocale);
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
