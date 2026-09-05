---
title: 0xJB
toc: false
---

<div class="hero-terminal">
  <canvas id="matrix-rain"></canvas>
  <div class="hero-content">

# 0xJB

Offensive security notes, CTF writeups, and red team research. Founder @ [AetherGuard Technologies](https://www.aetherguard.xyz/).

  </div>
</div>

{{< cards >}}
  {{< card link="writeups" title="Writeups" icon="book-open" subtitle="TryHackMe, HackTheBox, and other CTF walkthroughs" >}}
  {{< card link="research" title="Research" icon="beaker" subtitle="WiFi Pineapple, radio hacking, and MongoDB exposure research" >}}
  {{< card link="about" title="About" icon="user" subtitle="Who I am and what I work on" >}}
  {{< card link="https://ctf.aetherguard.xyz/" title="AetherGuard CTF" icon="flag" subtitle="Our CTF platform" >}}
  {{< card link="https://discord.gg/rDYw38Mmw" title="Discord" icon="discord" subtitle="Join the community" >}}
  {{< card link="mailto:jbernal@aetherguard.xyz" title="Email" icon="mail" subtitle="jbernal@aetherguard.xyz" >}}
{{< /cards >}}

<script>
(function () {
  var canvas = document.getElementById("matrix-rain");
  if (!canvas) return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  var ctx = canvas.getContext("2d");
  var parent = canvas.parentElement.parentElement;
  var fontSize = 15;
  var columns, drops;

  function resize() {
    canvas.width = parent.clientWidth;
    canvas.height = parent.clientHeight;
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(1);
  }
  resize();
  window.addEventListener("resize", resize);

  var chars = "01アイウエオカキクケコサシスセソABCDEFGHIJKLMNOPQRSTUVWXYZ";

  function draw() {
    ctx.fillStyle = "rgba(0, 0, 0, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#17cc74";
    ctx.font = fontSize + "px monospace";
    for (var i = 0; i < drops.length; i++) {
      var text = chars[Math.floor(Math.random() * chars.length)];
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);
      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }

  setInterval(draw, 50);
})();
</script>
