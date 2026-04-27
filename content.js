const hasPassword = document.querySelector('input[type="password"]');

if (hasPassword) {
  console.log("⚠️ Password field detected");

  const warning = document.createElement("div");
  warning.innerText = "⚠️ This page asks for your password";
  warning.style.position = "fixed";
  warning.style.top = "0";
  warning.style.left = "0";
  warning.style.right = "0";
  warning.style.background = "red";
  warning.style.color = "white";
  warning.style.padding = "10px";
  warning.style.zIndex = "9999";

  document.body.appendChild(warning);
}