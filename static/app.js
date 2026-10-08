document.addEventListener("submit", function (e) {
  var m = e.target.dataset.confirm;
  if (m && !confirm(m)) e.preventDefault();
});
