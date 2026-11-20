import "carbon-components/css/carbon-components.min.css";
import Vue from "vue";
import CarbonComponentsVue from "@carbon/vue";
import axios from "axios";
import VueAxios from "vue-axios";
import VueDateFns from "vue-date-fns";
import vueDebounce from "vue-debounce";
import ns8Lib, { Filters } from "@nethserver/ns8-ui-lib";

import App from "./App.vue";
import router from "./router";
import store from "./store";
import { initI18n } from "./i18n";

Vue.config.productionTip = false;

Vue.use(CarbonComponentsVue);
Vue.use(VueAxios, axios);
Vue.use(VueDateFns);
Vue.use(vueDebounce);
Vue.use(ns8Lib);

// Register standard NS8 global filters (byteFormat, humanFormat, secondsFormat, etc.)
Object.entries(Filters).forEach(([filterName, filterFn]) => {
  Vue.filter(filterName, filterFn);
});

const i18n = initI18n("en");

const app = new Vue({
  router,
  store,
  i18n,
  render: (h) => h(App),
}).$mount("#app");

window.ns8App = app;
