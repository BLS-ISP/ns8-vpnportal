<template>
  <div class="app-side-nav-content">
    <div class="instance-name-container">
      <div class="instance-name-title" :title="displayTitle">
        {{ displayTitle }}
      </div>
      <div v-if="instanceLabel && instanceName" class="instance-id-caption">
        {{ instanceName }}
      </div>
    </div>

    <cv-side-nav-items>
      <cv-side-nav-link
        @click="navigateTo('status')"
        :active="isLinkActive('status')"
      >
        <template v-slot:nav-icon>
          <Activity20 />
        </template>
        <span>{{ $t("status.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="navigateTo('peers')"
        :active="isLinkActive('peers')"
      >
        <template v-slot:nav-icon>
          <Events20 />
        </template>
        <span>{{ $t("peers.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="navigateTo('s2s')"
        :active="isLinkActive('s2s')"
      >
        <template v-slot:nav-icon>
          <Network_220 />
        </template>
        <span>{{ $t("s2s.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="navigateTo('audit-log')"
        :active="isLinkActive('audit-log')"
      >
        <template v-slot:nav-icon>
          <Catalog20 />
        </template>
        <span>{{ $t("audit.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="navigateTo('settings')"
        :active="isLinkActive('settings')"
      >
        <template v-slot:nav-icon>
          <Settings20 />
        </template>
        <span>{{ $t("settings.title") }}</span>
      </cv-side-nav-link>

      <cv-side-nav-link
        @click="navigateTo('about')"
        :active="isLinkActive('about')"
      >
        <template v-slot:nav-icon>
          <Information20 />
        </template>
        <span>{{ $t("about.title") }}</span>
      </cv-side-nav-link>
    </cv-side-nav-items>
  </div>
</template>

<script>
import { mapState } from "vuex";
import Activity20 from "@carbon/icons-vue/es/activity/20";
import Events20 from "@carbon/icons-vue/es/events/20";
import Network_220 from "@carbon/icons-vue/es/network--2/20";
import Catalog20 from "@carbon/icons-vue/es/catalog/20";
import Settings20 from "@carbon/icons-vue/es/settings/20";
import Information20 from "@carbon/icons-vue/es/information/20";
import { goToAppPage } from "@/utils/ns8";

export default {
  name: "AppSideMenuContent",
  components: {
    Activity20,
    Events20,
    Network_220,
    Catalog20,
    Settings20,
    Information20,
  },
  computed: {
    ...mapState(["instanceName", "instanceLabel", "core", "appName"]),
    displayTitle() {
      if (this.instanceLabel) {
        return this.instanceLabel;
      }
      if (this.instanceName) {
        return this.instanceName;
      }
      return this.appName;
    },
  },
  methods: {
    isLinkActive(page) {
      return this.$route && this.$route.path === `/${page}`;
    },
    navigateTo(page) {
      goToAppPage(this, page);
      this.$emit("navigate");
    },
  },
};
</script>

<style scoped lang="scss">
.instance-name-container {
  padding: 1rem 1rem 0.75rem 1rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  margin-bottom: 0.5rem;

  .instance-name-title {
    font-size: 1rem;
    font-weight: 600;
    color: #ffffff;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .instance-id-caption {
    margin-top: 0.2rem;
    font-size: 0.75rem;
    color: #c6c6c6;
  }
}
</style>
