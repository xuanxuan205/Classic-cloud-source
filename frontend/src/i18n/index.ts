import { ref, computed } from "vue"
import { zh } from "./zh"
import { en } from "./en"

const locale = ref<"zh" | "en">((localStorage.getItem("locale") as "zh" | "en") || "zh")

export function useI18n() {
  const t = computed(() => (locale.value === "zh" ? zh : en))

  function setLocale(lang: "zh" | "en") {
    locale.value = lang
    localStorage.setItem("locale", lang)
  }

  function toggleLocale() {
    setLocale(locale.value === "zh" ? "en" : "zh")
  }

  return { locale, t, setLocale, toggleLocale }
}