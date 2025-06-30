---
title: "About"
permalink: /about/
date: 2019-02-15
---

<style>
  body {
    background-color: #121212;
    color: #ffffff;
    font-family: Arial, sans-serif;
    text-align: center;
    margin: 0;
    padding: 0;
  }
  .container {
    max-width: 800px;
    margin: auto;
    padding: 20px;
  }
  .avatar {
    max-width: 150px;
    border-radius: 15px;
    border: 2px solid #ccc;
  }
  .text-box {
    text-align: left;
    padding: 15px;
    border: 2px solid #ccc;
    border-radius: 10px;
    background-color: #1e1e1e;
    margin: 20px auto;
    max-width: 90%;
    box-shadow: 0 4px 8px rgba(255, 255, 255, 0.2);
  }
  .matrix-text {
    font-family: 'Courier New', monospace;
    font-size: 20px;
    animation: color-change 3s infinite;
  }
  @keyframes color-change {
    0% { color: #00ff00; }
    25% { color: #9400d3; }
    50% { color: #dda0dd; }
    75% { color: #006400; }
    100% { color: #00ff00; }
  }
  .cert-image {
    max-width: 100%;
    border-radius: 15px;
    border: 2px solid #ccc;
  }
  .preview-box {
    margin-top: 15px;
    padding: 10px;
    background-color: #252525;
    border-radius: 10px;
    border: 2px solid #444;
    text-align: center;
  }
  .preview-box img {
    max-width: 100%;
    border-radius: 5px;
  }
  @media (max-width: 600px) {
    .text-box {
      font-size: 14px;
      padding: 10px;
    }
  }
</style>

<div class="container">
  <img class="avatar" src="https://404zzero.github.io/zzero.github.io//assets/images/avatar6.jpg" alt="Avatar">
  <div class="text-box">
    <p>Buenas, me llamo FallenAngel666 en las redes y soy un hacker ético español. Soy un entusiasta de la ciberseguridad, el hacking, el hardware y Linux en general.</p>
    <p>Actualmente estoy estudiando y, aparte, me estoy sacando por mi cuenta certificaciones de ciberseguridad. Básicamente paso mis días haciendo máquinas de Hack The Box.</p>
    <div class="preview-box">
      <a href="https://app.hackthebox.com/users/1728618" target="_blank">
        <img src="https://www.hackthebox.com/badge/image/1728618" alt="Hack The Box">
        <p>Visita mi perfil en Hack The Box</p>
      </a>
    </div>
  </div>
  <div class="text-box">
    <p>Actualmente (momento que escribo esto 2025) estoy cursando el FP superior de ASIR, para, nada más acabarlo, ir a la universidad y entrar a la ingeniería de ciberseguridad e incluso optar al doctorado.</p>
    <p>Mientras curso ASIR (porque la verdad se me hace muy fácil :3), aprovecho mi tiempo para estudiar y hacer certificaciones enfocadas al hacking. Actualmente estoy haciendo el CRTP, CRTE y CRTO (Realmente todas son muy seguidas y bastante calibre y reconocimiento) (aparte que a momento de que escribo esto realmente no me las saco por falta de dinero para qué mentir).</p>
    <p>Os muestro cómo es mi 'roadmap' de certificaciones en caso de que todo me salga bien a la primera y que disponga del dinero, claro.</p>
  </div>
  <img class="cert-image" src="https://404zzero.github.io/zzero.github.io//assets/images/cert2.png" alt="Certificaciones">
  <div class="text-box">
    <p>Ya un poco más sobre mis aficiones y demás: soy un loco del hardware y me encanta montar ordenadores de gama extrema y refrigeraciones líquidas custom. También soy fanático de la cultura asiática y nórdica.</p>
    <p>Y ya no sé qué más poner, así que... ¡HAPPY HACKING!</p>
  </div>
</div>

<script>
  function adjustLayout() {
      let screenWidth = window.innerWidth;
      let deviceType = screenWidth < 768 ? "Móvil" : "PC";
      document.querySelectorAll('.text-box').forEach(box => {
          box.style.width = screenWidth < 768 ? "95%" : "80%";
      });
      console.log(`Dispositivo detectado: ${deviceType}, Resolución: ${screenWidth}px`);
  }
  window.onload = adjustLayout;
  window.onresize = adjustLayout;
</script>
