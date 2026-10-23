const year = document.querySelector<HTMLElement>("#year");
if (year) year.textContent = String(new Date().getFullYear());

const apiStatus = document.querySelector<HTMLElement>("[data-api-status]");
if (apiStatus) {
  apiStatus.textContent = "Backend pendiente de conectar · No se realizan consultas reales.";
}

document.querySelectorAll<HTMLFormElement>("[data-lab-form]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = form.querySelector<HTMLElement>("[data-message]");
    if (message) message.textContent = "Módulo visual preparado. La conexión segura con Cloudflare Workers se añadirá en la siguiente fase.";
  });
});
