(function () {
  var burger = document.getElementById("burger");
  var menu = document.getElementById("mm");

  if (burger && menu) {
    burger.addEventListener("click", function () {
      menu.classList.toggle("open");
    });

    menu.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        menu.classList.remove("open");
      });
    });
  }

  document.querySelectorAll("#yr").forEach(function (year) {
    year.textContent = String(new Date().getFullYear());
  });

  var revealItems = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("in");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14 }
    );

    revealItems.forEach(function (item) {
      observer.observe(item);
    });
  } else {
    revealItems.forEach(function (item) {
      item.classList.add("in");
    });
  }

  document.querySelectorAll(".qa button").forEach(function (button) {
    button.addEventListener("click", function () {
      var item = button.closest(".qa");
      if (item) {
        item.classList.toggle("open");
      }
    });
  });

  var billingToggle = document.getElementById("billToggle");
  var monthlyButton = document.getElementById("billMonthly");
  var annualButton = document.getElementById("billAnnual");

  function setBilling(period) {
    var isAnnual = period === "a";

    if (billingToggle) {
      billingToggle.classList.toggle("annual", isAnnual);
    }
    if (monthlyButton) {
      monthlyButton.classList.toggle("on", !isAnnual);
    }
    if (annualButton) {
      annualButton.classList.toggle("on", isAnnual);
    }

    document.querySelectorAll("[data-m][data-a]").forEach(function (item) {
      item.textContent = item.getAttribute("data-" + period);
    });
  }

  if (monthlyButton && annualButton) {
    monthlyButton.addEventListener("click", function () {
      setBilling("m");
    });
    annualButton.addEventListener("click", function () {
      setBilling("a");
    });
  }

  var latency = document.getElementById("lat");
  var pii = document.querySelectorAll("#inNode .pii");
  if (latency && pii.length) {
    var values = ["+32ms", "+38ms", "+41ms", "+36ms"];
    var index = 0;

    setInterval(function () {
      index = (index + 1) % values.length;
      latency.textContent = values[index];

      pii.forEach(function (item) {
        item.classList.add("masked");
        item.textContent = "------";
      });

      window.setTimeout(function () {
        pii.forEach(function (item) {
          item.classList.remove("masked");
          item.textContent = item.getAttribute("data-real");
        });
      }, 700);
    }, 2600);
  }
})();
