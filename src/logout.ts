export {};
const isPortal = location.hostname === "monkeytools.es" ||
  location.hostname === "www.monkeytools.es" ||
  location.hostname.startsWith("monkeytools-portal.");

if (isPortal) {
  const side = document.querySelector<HTMLElement>(".side-navigation");
  if (side) {
    const btn = document.createElement("button");
    btn.textContent = "Cerrar sesión";
    btn.type = "button";
    btn.className = "mt-logout";
    btn.addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
      location.replace("/login/");
    });
    side.append(btn);
  }

  // Detecta la revocación de sesión en otro navegador o dispositivo.
  // Esta consulta NO renueva el plazo de 9 horas de inactividad.
  let checking = false;
  async function checkSession() {
    if (checking || document.visibilityState === "hidden") return;
    checking = true;
    try {
      const res = await fetch("/api/auth/status", {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (res.status === 401 || res.status === 403) {
        location.replace("/login/?session=expired");
      }
      // Un error de red temporal no debe expulsar al usuario.
    } catch {
      // Se reintentará en la siguiente comprobación.
    } finally {
      checking = false;
    }
  }

  void checkSession();
  window.setInterval(() => { void checkSession(); }, 15000);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") void checkSession();
  });
  window.addEventListener("focus", () => { void checkSession(); });
}
