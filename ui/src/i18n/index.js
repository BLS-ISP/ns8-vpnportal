import Vue from "vue";
import VueI18n from "vue-i18n";
import axios from "axios";
import enMessages from "../../public/i18n/en/translation.json";
import deMessages from "../../public/i18n/de/translation.json";

Vue.use(VueI18n);

const loadedLanguages = ["en", "de"];

export function initI18n(locale = "en") {
  const initialLocale = loadedLanguages.includes(locale) ? locale : "en";
  return new VueI18n({
    locale: initialLocale,
    fallbackLocale: "en",
    silentFallbackWarn: true,
    messages: {
      en: enMessages,
      de: deMessages,
    },
  });
}

export async function loadLanguageAsync(i18n, lang) {
  if (!lang) {
    return "en";
  }
  const normalizedLang = lang.split("-")[0].toLowerCase();

  if (i18n.locale === normalizedLang && loadedLanguages.includes(normalizedLang)) {
    return normalizedLang;
  }

  if (loadedLanguages.includes(normalizedLang)) {
    i18n.locale = normalizedLang;
    document.querySelector("html")?.setAttribute("lang", normalizedLang);
    return normalizedLang;
  }

  try {
    const response = await axios.get(`./i18n/${normalizedLang}/translation.json`);
    if (response && response.data) {
      i18n.setLocaleMessage(normalizedLang, response.data);
      loadedLanguages.push(normalizedLang);
      i18n.locale = normalizedLang;
      document.querySelector("html")?.setAttribute("lang", normalizedLang);
      return normalizedLang;
    }
  } catch (err) {
    console.warn(
      `Cannot load translation for ${normalizedLang}, falling back to en`,
      err
    );
  }

  i18n.locale = "en";
  document.querySelector("html")?.setAttribute("lang", "en");
  return "en";
}
