/**
 * Shared NS8 Cockpit UI helpers for task safety, formatting, and navigation.
 */

export function to(promise) {
  return promise
    .then((data) => [null, data])
    .catch((err) => [err, undefined]);
}

export function getParentCore() {
  try {
    if (
      typeof window !== "undefined" &&
      window.parent &&
      window.parent !== window &&
      window.parent.core &&
      window.parent.core.$root
    ) {
      return window.parent.core;
    }
    if (
      typeof window !== "undefined" &&
      window.parent &&
      window.parent.core &&
      window.parent.core.$root
    ) {
      return window.parent.core;
    }
  } catch (err) {
    // Ignore cross-origin frame access errors in standalone preview
  }
  return null;
}

export function goToAppPage(vm, pageName) {
  const targetRoute = pageName.startsWith("/") ? pageName : `/${pageName}`;
  const cleanPage = pageName.replace(/^\//, "");

  if (vm.core && vm.core.$router && vm.instanceName) {
    const targetCorePath = `/apps/${vm.instanceName}?page=${cleanPage}`;
    if (vm.core.$route && vm.core.$route.fullPath !== targetCorePath) {
      vm.core.$router.push(targetCorePath).catch(() => {});
    }
  }

  if (vm.$route && vm.$route.path !== targetRoute) {
    vm.$router.push(targetRoute).catch(() => {});
  }
}

export function formatTransferBytes(value) {
  if (value === null || value === undefined || value === "") {
    return "0 B";
  }
  const num = Number(value);
  if (Number.isNaN(num) || num <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let scaled = num;
  while (scaled >= 1024 && idx < units.length - 1) {
    scaled /= 1024;
    idx += 1;
  }
  if (idx === 0) {
    return `${Math.round(scaled)} B`;
  }
  return `${scaled.toFixed(scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2)} ${units[idx]}`;
}

export function formatContainerImageSize(size, byteFormatFilter) {
  if (size === null || size === undefined || size === "") {
    return "-";
  }
  if (typeof size === "number" && !Number.isNaN(size)) {
    return byteFormatFilter ? byteFormatFilter(size) : `${size} B`;
  }
  if (typeof size === "string") {
    const trimmed = size.trim();
    if (!trimmed) {
      return "-";
    }
    if (/^\d+$/.test(trimmed)) {
      const parsed = Number(trimmed);
      return byteFormatFilter ? byteFormatFilter(parsed) : `${parsed} B`;
    }
    return trimmed;
  }
  return String(size);
}

export function formatDateTimeSafe(isoValue, locale = "en", neverLabel = "-") {
  if (!isoValue) {
    return neverLabel;
  }
  const dateObj =
    typeof isoValue === "number"
      ? new Date(isoValue < 1e12 ? isoValue * 1000 : isoValue)
      : new Date(isoValue);

  if (Number.isNaN(dateObj.getTime())) {
    return String(isoValue);
  }

  try {
    return new Intl.DateTimeFormat(locale || "en", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(dateObj);
  } catch (err) {
    return dateObj.toLocaleString();
  }
}

export function formatRelativeHandshake(
  isoValue,
  locale = "en",
  neverLabel = "Never",
  justNowLabel = "Just now"
) {
  if (!isoValue) {
    return neverLabel;
  }
  const dateObj =
    typeof isoValue === "number"
      ? new Date(isoValue < 1e12 ? isoValue * 1000 : isoValue)
      : new Date(isoValue);

  if (Number.isNaN(dateObj.getTime())) {
    return String(isoValue);
  }

  const diffSeconds = Math.max(
    0,
    Math.floor((Date.now() - dateObj.getTime()) / 1000)
  );

  if (diffSeconds < 15) {
    return justNowLabel;
  }

  const isDe = (locale || "").toLowerCase().startsWith("de");
  if (diffSeconds < 60) {
    return isDe ? `vor ${diffSeconds} Sek.` : `${diffSeconds}s ago`;
  }
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    return isDe ? `vor ${diffMinutes} Min.` : `${diffMinutes}m ago`;
  }
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return isDe ? `vor ${diffHours} Std.` : `${diffHours}h ago`;
  }

  return formatDateTimeSafe(isoValue, locale, neverLabel);
}

export function resolveValidationError(vm, sectionPrefix, validationError) {
  if (!validationError) {
    return vm.$t("error.validation_error");
  }
  const errCode = validationError.error || "validation_error";
  const value = validationError.value !== undefined ? validationError.value : "";

  const sectionKey = `${sectionPrefix}.${errCode}`;
  if (vm.$te(sectionKey)) {
    return vm.$t(sectionKey, { value });
  }

  const errorKey = `error.${errCode}`;
  if (vm.$te(errorKey)) {
    return vm.$t(errorKey, { value });
  }

  return String(errCode);
}
