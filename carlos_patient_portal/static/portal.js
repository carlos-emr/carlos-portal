document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }

  const revealButton = event.target.closest("[data-reveal-url][data-reveal-target]");
  if (!(revealButton instanceof HTMLButtonElement)) {
    return;
  }

  const revealUrl = revealButton.dataset.revealUrl;
  const targetId = revealButton.dataset.revealTarget;
  const csrfToken = revealButton.dataset.csrfToken;
  const target = targetId ? document.getElementById(targetId) : null;
  const passwordInput = document.querySelector("[data-reveal-password]");
  if (
    !revealUrl
    || !csrfToken
    || !(target instanceof HTMLElement)
    || !(passwordInput instanceof HTMLInputElement)
  ) {
    return;
  }
  if (!passwordInput.value) {
    passwordInput.focus();
    return;
  }

  revealButton.disabled = true;
  revealButton.textContent = revealButton.dataset.revealingLabel || "Revealing...";
  const requestBody = new URLSearchParams({
    csrf_token: csrfToken,
    current_password: passwordInput.value,
  });
  passwordInput.value = "";
  // This box has no form, so nothing else hides it again once it is sent.
  for (const toggle of passwordToggles) {
    if (passwordToggleInputs(toggle).includes(passwordInput)) {
      setPasswordsShown(toggle, false);
    }
  }
  void fetch(revealUrl, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: requestBody.toString(),
  })
    .then((response) => {
      if (response.status === 401) {
        window.location.assign(response.headers.get("Location") || "/");
        throw new Error("Portal session expired");
      }
      if (!response.ok) {
        throw new Error("reveal failed");
      }
      return response.json();
    })
    .then((payload) => {
      if (
        typeof payload !== "object"
        || payload === null
        || typeof payload.passphrase !== "string"
      ) {
        throw new Error("invalid reveal response");
      }
      target.textContent = payload.passphrase;
      const copyButton = target.parentElement?.querySelector("[data-copy-target]");
      if (copyButton instanceof HTMLButtonElement) {
        copyButton.hidden = false;
      }
      revealButton.hidden = true;
      target.focus();
    })
    .catch(() => {
      revealButton.textContent = (
        revealButton.dataset.revealFailedLabel || "Password could not be revealed."
      );
      window.setTimeout(() => {
        revealButton.textContent = revealButton.dataset.revealLabel || "Reveal";
        revealButton.disabled = false;
      }, 2500);
    });
});

// "Show password" controls (#29). Each button names the boxes it controls in aria-controls. The
// buttons are hidden in the HTML and revealed here, so without JavaScript the boxes just stay hidden.
const passwordToggles = Array.from(document.querySelectorAll("[data-password-toggle]")).filter(
  (toggle) => toggle instanceof HTMLButtonElement
);
const passwordToggleInputs = (toggle) => (toggle.getAttribute("aria-controls") || "")
  .split(/\s+/)
  .map((id) => document.getElementById(id))
  .filter((input) => input instanceof HTMLInputElement);
// The boxes themselves say whether they are shown; the button's words say what it does next
// ("Show password" / "Hide password"), with no aria-pressed (D133, as GOV.UK does it).
const passwordsShown = (toggle) =>
  passwordToggleInputs(toggle).some((input) => input.type === "text");
const setPasswordsShown = (toggle, shown) => {
  for (const input of passwordToggleInputs(toggle)) {
    input.type = shown ? "text" : "password";
  }
  toggle.textContent = shown
    ? toggle.dataset.hideLabel || "Hide password"
    : toggle.dataset.showLabel || "Show password";
};
for (const toggle of passwordToggles) {
  toggle.hidden = false;
}
document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }
  const toggle = event.target.closest("[data-password-toggle]");
  if (!(toggle instanceof HTMLButtonElement)) {
    return;
  }
  setPasswordsShown(toggle, !passwordsShown(toggle));
});
// Hide the boxes again when their form is sent and when the page comes back from the
// back/forward cache, so a password is not left showing on a shared screen.
document.addEventListener(
  "submit",
  (event) => {
    if (!(event.target instanceof HTMLFormElement)) {
      return;
    }
    for (const toggle of passwordToggles) {
      if (passwordToggleInputs(toggle).some((input) => event.target.contains(input))) {
        setPasswordsShown(toggle, false);
      }
    }
  },
  true
);
window.addEventListener("pageshow", () => {
  for (const toggle of passwordToggles) {
    setPasswordsShown(toggle, false);
  }
});

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }

  const copyButton = event.target.closest("[data-copy-target]");
  if (!(copyButton instanceof HTMLButtonElement)) {
    return;
  }

  const targetId = copyButton.dataset.copyTarget;
  const target = targetId ? document.getElementById(targetId) : null;
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const copyValue = (
    target instanceof HTMLInputElement ? target.value : target.textContent || ""
  ).trim();
  if (target instanceof HTMLInputElement) {
    target.select();
    target.setSelectionRange(0, target.value.length);
  }
  const originalText = copyButton.textContent || copyButton.dataset.copyLabel || "Copy";
  const copyPromise = navigator.clipboard
    ? navigator.clipboard.writeText(copyValue)
    : Promise.reject(new Error("clipboard unavailable"));
  void copyPromise
    .then(() => {
      copyButton.textContent = copyButton.dataset.copiedLabel || "Copied";
    })
    .catch(() => {
      copyButton.textContent = (
        copyButton.dataset.copyFailedLabel || "Select and copy manually"
      );
      target.focus();
      const selection = window.getSelection();
      if (!(target instanceof HTMLInputElement) && selection) {
        const range = document.createRange();
        range.selectNodeContents(target);
        selection.removeAllRanges();
        selection.addRange(range);
      }
    })
    .finally(() => {
      window.setTimeout(() => {
        copyButton.textContent = originalText;
      }, 2500);
    });
});

const resetTokenForm = document.querySelector("[data-reset-token-form]");
const resetTokenInput = document.querySelector("[data-reset-token]");
const resetTokenError = document.querySelector("[data-reset-token-error]");

if (
  resetTokenForm instanceof HTMLFormElement
  && resetTokenInput instanceof HTMLInputElement
) {
  const fragmentValues = new URLSearchParams(window.location.hash.slice(1));
  const fragmentResetToken = fragmentValues.get("token") || "";
  const resetToken = fragmentResetToken || resetTokenInput.value;
  resetTokenInput.value = resetToken;
  if (fragmentResetToken) {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  }
  if (!resetToken && resetTokenError instanceof HTMLElement) {
    resetTokenError.hidden = false;
  }
  // A language link reloads this page through a redirect, and the token must not reach the
  // server. So it rides in the link's fragment, which the browser keeps across a redirect whose
  // Location has none, and the code above moves it into the form again. Only links that come back
  // to this same page get it, so it never lands in another page's address bar.
  if (resetToken) {
    document.querySelectorAll(".language-switch a[href]").forEach((link) => {
      if (!(link instanceof HTMLAnchorElement)) {
        return;
      }
      const target = new URL(link.href, window.location.href);
      if (target.searchParams.get("next") === window.location.pathname) {
        target.hash = new URLSearchParams({ token: resetToken }).toString();
        link.href = target.toString();
      }
    });
  }
  resetTokenForm.addEventListener("submit", (event) => {
    if (!resetTokenInput.value) {
      event.preventDefault();
      if (resetTokenError instanceof HTMLElement) {
        resetTokenError.hidden = false;
        resetTokenError.focus();
      }
    }
  });
}

const portalMessageModal = document.getElementById("portal-message-modal");
const portalMessageTitle = document.getElementById("portal-message-title");
const portalMessageBody = document.getElementById("portal-message-body");
let portalMessageOpener = null;
let inertBackgroundElements = [];

function setPortalBackgroundInert() {
  if (!(portalMessageModal instanceof HTMLElement)) {
    return;
  }
  inertBackgroundElements = [];
  let activeBranch = portalMessageModal;
  let parent = activeBranch.parentElement;
  while (parent instanceof HTMLElement) {
    for (const sibling of parent.children) {
      if (sibling !== activeBranch && sibling instanceof HTMLElement && !sibling.inert) {
        sibling.inert = true;
        inertBackgroundElements.push(sibling);
      }
    }
    activeBranch = parent;
    parent = parent.parentElement;
  }
}

function restorePortalBackground() {
  for (const element of inertBackgroundElements) {
    element.inert = false;
  }
  inertBackgroundElements = [];
}

function hidePortalMessageModal() {
  if (!(portalMessageModal instanceof HTMLElement) || portalMessageModal.hidden) {
    return;
  }
  portalMessageModal.hidden = true;
  restorePortalBackground();
  if (portalMessageOpener instanceof HTMLElement) {
    portalMessageOpener.focus();
  }
  portalMessageOpener = null;
}

function showPortalMessageModal(title, message, opener) {
  if (
    !(portalMessageModal instanceof HTMLElement)
    || !(portalMessageTitle instanceof HTMLElement)
    || !(portalMessageBody instanceof HTMLElement)
  ) {
    return;
  }

  portalMessageTitle.textContent = title;
  portalMessageBody.textContent = message;
  portalMessageOpener = opener instanceof HTMLElement ? opener : null;
  portalMessageModal.hidden = false;
  setPortalBackgroundInert();
  const closeButton = portalMessageModal.querySelector("[data-modal-close]");
  if (closeButton instanceof HTMLElement) {
    closeButton.focus();
  }
}

document.addEventListener("click", (event) => {
  if (!(event.target instanceof Element)) {
    return;
  }

  const modalTrigger = event.target.closest("[data-modal-title][data-modal-message]");
  if (modalTrigger instanceof HTMLElement) {
    event.preventDefault();
    showPortalMessageModal(
      modalTrigger.dataset.modalTitle || "",
      modalTrigger.dataset.modalMessage || "",
      modalTrigger,
    );
    return;
  }

  const modalClose = event.target.closest("[data-modal-close]");
  if (modalClose instanceof HTMLElement) {
    event.preventDefault();
    hidePortalMessageModal();
    return;
  }

  if (event.target === portalMessageModal) {
    hidePortalMessageModal();
  }
});

document.addEventListener("keydown", (event) => {
  if (!(portalMessageModal instanceof HTMLElement) || portalMessageModal.hidden) {
    return;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    hidePortalMessageModal();
    return;
  }
  if (event.key !== "Tab") {
    return;
  }
  const focusableElements = [...portalMessageModal.querySelectorAll(
    "a[href], button:not([disabled]), input:not([disabled]), "
      + "select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
  )].filter((element) => element instanceof HTMLElement && !element.hidden);
  if (focusableElements.length === 0) {
    event.preventDefault();
    return;
  }
  const firstElement = focusableElements[0];
  const lastElement = focusableElements.at(-1);
  if (event.shiftKey && document.activeElement === firstElement) {
    event.preventDefault();
    lastElement.focus();
  } else if (!event.shiftKey && document.activeElement === lastElement) {
    event.preventDefault();
    firstElement.focus();
  }
});

const activationMfaMethod = document.querySelector("[data-activation-mfa-method]");
const activationPhone = document.querySelector("[data-activation-phone]");
if (activationMfaMethod instanceof HTMLSelectElement && activationPhone instanceof HTMLInputElement) {
  const syncActivationPhoneRequirement = () => {
    const required = activationMfaMethod.value === "sms";
    activationPhone.required = required;
    activationPhone.setAttribute("aria-required", String(required));
  };
  activationMfaMethod.addEventListener("change", syncActivationPhoneRequirement);
  syncActivationPhoneRequirement();
}

// Keep an open waiting page honest even when the patient does not reload it.
const bookingStatus = document.querySelector("[data-booking-wait-ms]");
if (bookingStatus instanceof HTMLElement) {
  const remainingMs = Number(bookingStatus.dataset.bookingWaitMs);
  const overdueNotice = bookingStatus.dataset.bookingOverdueNotice;
  if (Number.isFinite(remainingMs) && remainingMs >= 0 && overdueNotice) {
    window.setTimeout(() => {
      bookingStatus.textContent = overdueNotice;
    }, remainingMs);
  }
}
