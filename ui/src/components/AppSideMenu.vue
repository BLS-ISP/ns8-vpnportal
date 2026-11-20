<template>
  <cv-side-nav id="side-nav" fixed expanded class="app-side-nav">
    <AppSideMenuContent />
  </cv-side-nav>
</template>

<script>
import AppSideMenuContent from "./AppSideMenuContent.vue";

export default {
  name: "AppSideMenu",
  components: {
    AppSideMenuContent,
  },
};
</script>

<style scoped lang="scss">
@import "../styles/variables";

.app-side-nav {
  background-color: #161616;
  color: #ffffff;
  z-index: 1000;
  top: 0;
  width: $app-side-nav-width;
  display: none;

  @media (min-width: $breakpoint-large) {
    display: block;
  }
}
</style>

<style lang="scss">
.app-side-nav {
  .bx--side-nav__link > .bx--side-nav__link-text {
    color: #f4f4f4 !important;
  }

  .bx--side-nav__icon > svg {
    fill: #f4f4f4 !important;
  }

  .bx--side-nav__link:hover,
  .bx--side-nav__link[aria-current="page"],
  .bx--side-nav__link--current {
    background-color: #353535 !important;

    .bx--side-nav__link-text {
      color: #ffffff !important;
    }
  }
}
</style>
