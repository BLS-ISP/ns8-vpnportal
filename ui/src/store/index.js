import Vue from "vue";
import Vuex from "vuex";

Vue.use(Vuex);

export default new Vuex.Store({
  state: {
    instanceName: "",
    instanceLabel: "",
    core: null,
    appName: "Business Roadwarrior VPN",
    instanceStatus: null,
    isAppConfigured: true,
  },
  mutations: {
    setInstanceName(state, instanceName) {
      state.instanceName = instanceName;
    },
    setInstanceLabel(state, instanceLabel) {
      state.instanceLabel = instanceLabel;
    },
    setCore(state, core) {
      state.core = core;
    },
    setAppName(state, appName) {
      state.appName = appName;
    },
    setInstanceStatus(state, instanceStatus) {
      state.instanceStatus = instanceStatus;
    },
    setAppConfigured(state, isConfigured) {
      state.isAppConfigured = Boolean(isConfigured);
    },
  },
  actions: {
    setInstanceNameInStore({ commit }, instanceName) {
      commit("setInstanceName", instanceName);
    },
    setInstanceLabelInStore({ commit }, instanceLabel) {
      commit("setInstanceLabel", instanceLabel);
    },
    setCoreInStore({ commit }, core) {
      commit("setCore", core);
    },
    setAppNameInStore({ commit }, appName) {
      commit("setAppName", appName);
    },
    setInstanceStatusInStore({ commit }, instanceStatus) {
      commit("setInstanceStatus", instanceStatus);
    },
    setAppConfiguredInStore({ commit }, isConfigured) {
      commit("setAppConfigured", isConfigured);
    },
  },
});
