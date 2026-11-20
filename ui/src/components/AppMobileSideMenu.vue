<template>
  <transition name="slide-menu">
    <div v-if="isShown" class="mobile-side-menu-backdrop" @click.self="$emit('close')">
      <div class="mobile-side-menu app-side-nav">
        <div class="mobile-close-bar">
          <cv-icon-button
            kind="ghost"
            size="sm"
            :icon="Close20"
            :label="$t('common.close')"
            @click="$emit('close')"
          />
        </div>
        <AppSideMenuContent @navigate="$emit('close')" />
      </div>
    </div>
  </transition>
</template>

<script>
import Close20 from "@carbon/icons-vue/es/close/20";
import AppSideMenuContent from "./AppSideMenuContent.vue";

export default {
  name: "AppMobileSideMenu",
  components: {
    AppSideMenuContent,
  },
  props: {
    isShown: {
      type: Boolean,
      default: false,
    },
  },
  data() {
    return {
      Close20,
    };
  },
};
</script>

<style scoped lang="scss">
@import "../styles/variables";

.mobile-side-menu-backdrop {
  position: fixed;
  inset: 0;
  background-color: rgba(22, 22, 22, 0.5);
  z-index: 9000;

  @media (min-width: $breakpoint-large) {
    display: none;
  }
}

.mobile-side-menu {
  width: $app-side-nav-width;
  height: 100%;
  background-color: #161616;
  color: #ffffff;
  overflow-y: auto;
}

.mobile-close-bar {
  display: flex;
  justify-content: flex-end;
  padding: 0.25rem 0.5rem 0 0.5rem;
}

.slide-menu-enter-active,
.slide-menu-leave-active {
  transition: opacity 0.2s ease;
}

.slide-menu-enter,
.slide-menu-leave-to {
  opacity: 0;
}
</style>
