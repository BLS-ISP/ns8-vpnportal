<template>
  <cv-grid fullWidth>
    <cv-row>
      <cv-column class="page-title">
        <h2>{{ $t("about.title") }}</h2>
      </cv-column>
    </cv-row>

    <cv-row class="mg-bottom-md">
      <cv-column>
        <cv-tile kind="standard" :light="true" class="about-tile">
          <cv-skeleton-text
            v-if="loading.metadata"
            :paragraph="true"
            :line-count="6"
          />

          <template v-else>
            <div class="about-header">
              <img
                :src="moduleDefaultLogo"
                :alt="metadata.name || appName"
                class="about-logo-image"
              />
              <div>
                <h3>{{ metadata.name || appName }}</h3>
                <p class="about-description">{{ localizedDescription }}</p>
              </div>
            </div>

            <div class="key-value-grid mg-top-lg mg-bottom-lg">
              <div v-if="categoriesText" class="kv-item">
                <div class="kv-label">{{ $t("about.categories") }}</div>
                <div class="kv-value">{{ categoriesText }}</div>
              </div>

              <div v-if="metadata.source" class="kv-item">
                <div class="kv-label">{{ $t("about.source_package") }}</div>
                <div class="kv-value monospace">{{ metadata.source }}</div>
              </div>

              <div
                v-if="metadata.authors && metadata.authors.length"
                class="kv-item"
              >
                <div class="kv-label">{{ $t("about.authors") }}</div>
                <div class="kv-value">
                  <div v-for="(author, idx) in metadata.authors" :key="idx">
                    {{ author.name }}
                    <span v-if="author.email" class="author-email">
                      ({{ author.email }})
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div class="external-links-row mg-bottom-lg">
              <cv-link
                v-if="metadata.docs && metadata.docs.documentation_url"
                :href="metadata.docs.documentation_url"
                target="_blank"
                rel="noopener noreferrer"
                class="external-link-item"
              >
                <span>{{ $t("about.documentation") }}</span>
                <Launch20 class="launch-icon" />
              </cv-link>

              <cv-link
                v-if="metadata.docs && metadata.docs.bug_url"
                :href="metadata.docs.bug_url"
                target="_blank"
                rel="noopener noreferrer"
                class="external-link-item"
              >
                <span>{{ $t("about.bug_tracker") }}</span>
                <Launch20 class="launch-icon" />
              </cv-link>

              <cv-link
                v-if="metadata.docs && metadata.docs.code_url"
                :href="metadata.docs.code_url"
                target="_blank"
                rel="noopener noreferrer"
                class="external-link-item"
              >
                <span>{{ $t("about.source_code") }}</span>
                <Launch20 class="launch-icon" />
              </cv-link>
            </div>

            <div class="highlights-panel">
              <h4>{{ $t("about.highlights_title") }}</h4>
              <ul class="highlights-list mg-top-sm">
                <li>{{ $t("about.highlight_wireguard") }}</li>
                <li>{{ $t("about.highlight_ldap") }}</li>
                <li>{{ $t("about.highlight_firewall") }}</li>
                <li>{{ $t("about.highlight_audit") }}</li>
                <li>{{ $t("about.highlight_backup") }}</li>
              </ul>
            </div>
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
  IconService,
  UtilService,
} from "@nethserver/ns8-ui-lib";
import Launch20 from "@carbon/icons-vue/es/launch/20";
import moduleDefaultLogo from "@/assets/module_default_logo.png";

export default {
  name: "About",
  components: {
    Launch20,
  },
  mixins: [IconService, UtilService, QueryParamService, PageTitleService],
  pageTitle() {
    return this.$t("about.title") + " - " + this.appName;
  },
  data() {
    return {
      q: {
        page: "about",
      },
      urlCheckInterval: null,
      moduleDefaultLogo,
      metadata: {
        name: "",
        description: {},
        categories: [],
        authors: [],
        docs: {},
        source: "",
      },
      loading: {
        metadata: false,
      },
    };
  },
  computed: {
    ...mapState(["instanceName", "core", "appName"]),
    localizedDescription() {
      const desc = this.metadata && this.metadata.description;
      if (desc && typeof desc === "object") {
        const lang = (this.$i18n.locale || "en").split("-")[0];
        if (desc[lang]) {
          return desc[lang];
        }
        if (desc.en) {
          return desc.en;
        }
      }
      return this.$t("about.description_fallback");
    },
    categoriesText() {
      if (!this.metadata || !Array.isArray(this.metadata.categories)) {
        return "";
      }
      if (this.core) {
        return this.getAppCategories(this.metadata, this.core);
      }
      return this.metadata.categories.join(", ");
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
    this.loadMetadata();
  },
  methods: {
    async loadMetadata() {
      this.loading.metadata = true;
      try {
        const response = await this.axios.get("./metadata.json");
        if (response && response.data) {
          this.metadata = response.data;
        }
      } catch (err) {
        console.error("Cannot retrieve metadata.json", err);
      } finally {
        this.loading.metadata = false;
      }
    },
  },
};
</script>

<style scoped lang="scss">
.page-title {
  margin-top: 1.5rem;
  margin-bottom: 1rem;
}

.about-tile {
  padding: 1.5rem;
}

.about-header {
  display: flex;
  align-items: flex-start;
  gap: 1rem;

  .about-logo-image {
    width: 3.5rem;
    height: 3.5rem;
    object-fit: contain;
    flex-shrink: 0;
  }

  h3 {
    margin: 0 0 0.35rem 0;
  }

  .about-description {
    margin: 0;
    color: #525252;
    max-width: 48rem;
    line-height: 1.5;
  }
}

.author-email {
  color: #525252;
  font-size: 0.875rem;
}

.external-links-row {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;

  .external-link-item {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-weight: 500;

    .launch-icon {
      fill: currentColor;
    }
  }
}

.highlights-panel {
  background-color: #f8f9fb;
  border: 1px solid #e0e0e0;
  padding: 1rem 1.25rem;

  h4 {
    margin: 0;
    font-size: 1rem;
  }

  .highlights-list {
    margin-bottom: 0;
    padding-left: 1.25rem;
    line-height: 1.65;
    color: #161616;
  }
}
</style>
