import Vue from "vue";
import VueRouter from "vue-router";
import Status from "../views/Status.vue";
import Peers from "../views/Peers.vue";
import SiteToSite from "../views/SiteToSite.vue";
import AuditLog from "../views/AuditLog.vue";
import Settings from "../views/Settings.vue";
import About from "../views/About.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    redirect: "/status",
  },
  {
    path: "/status",
    name: "Status",
    component: Status,
  },
  {
    path: "/peers",
    name: "Peers",
    component: Peers,
  },
  {
    path: "/s2s",
    name: "SiteToSite",
    component: SiteToSite,
  },
  {
    path: "/audit-log",
    name: "AuditLog",
    component: AuditLog,
  },
  {
    path: "/settings",
    name: "Settings",
    component: Settings,
  },
  {
    path: "/about",
    name: "About",
    component: About,
  },
];

const router = new VueRouter({
  base: process.env.BASE_URL,
  routes,
});

export default router;
