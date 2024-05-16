var JWT = window.sessionStorage.getItem('JWT');
	if (JWT == null || JWT == ''){
		window.location.href = "login.html";
	}
var xhr = new XMLHttpRequest();
var url = "http://localhost:5000/cliente";
xhr.open("GET", url, true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.setRequestHeader("Token", window.sessionStorage.getItem('JWT'));
xhr.onload = function () {
		if (xhr.status !== 200) {
            alert("Token expirado, faça login novamente!");
			window.sessionStorage.removeItem('JWT');
			window.location.href = 'login.html';
		}
};
xhr.responseType="text";
xhr.send();    