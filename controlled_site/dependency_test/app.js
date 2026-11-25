fetch("/api/fetch")
  .then((response) => response.json())
  .then((data) => {
    document.querySelector("#result").textContent = data.message;
  });

const xhr = new XMLHttpRequest();
xhr.open("GET", "/api/xhr");
xhr.onload = () => {
  document.querySelector("#result").dataset.xhr = xhr.responseText;
};
xhr.send();
