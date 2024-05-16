$(document).ready(function() {
    var url = "http://127.0.0.1:5000/cliente";
    var xhr = new XMLHttpRequest();

    function Verifica_campos(nome, usuario, senha, genero, data_nascimento) {
        const isBelowThreshold = (currentValue) => currentValue == true;
        campos_para_preencher = [nome, usuario, senha, genero, data_nascimento]
        verificacao_list = []

        for(num_campo in campos_para_preencher) {
            if (campos_para_preencher[num_campo] == null || campos_para_preencher[num_campo] == '') {
                verificacao_list.push(false);
                
            } else {
                verificacao_list.push(true);
            }
        }
        if (verificacao_list.every(isBelowThreshold) == true) {
            return true
        } return false
    }

    // $('#usuario').keyup(  function () {
    //     var usuario = document.getElementById("usuario").value;
    //     xhr.open("POST", url + "/usuario_existente", true);
    //     xhr.setRequestHeader("Content-Type", "application/json");
    //     xhr.onreadystatechange = function () {
    //         if (xhr.readyState === 4 && xhr.status === 200) {
    //             $("#usuario").css({"border": "#31FF4E 4px solid"});
                
    //         }if(xhr.readyState === 4 && xhr.status === 401){
    //             $("#usuario").css({"border": "#FF0F0F 4px solid"});
    //         }
    //     }

    //     var data = JSON.stringify({"usuario": usuario});
    //     xhr.send(data);
    // })
    
    $('#Botao').click(  function () {
        var nome = document.getElementById("nome").value;
        var usuario = document.getElementById("usuario").value;
        var senha = document.getElementById("senha").value;
        var genero = document.getElementById("genero").value;
        var data_nascimento = document.getElementById("data_nascimento").value;
        verificacao = Verifica_campos(nome, usuario, senha, genero, data_nascimento)
        
        if (verificacao == true) {
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                alert("Sucesso ao cadastrar-se")
                window.location.href = "Login.html";

            }if(xhr.readyState === 4 && xhr.status === 401){
              alert("Erro ao cadastrar-se")
            }};

            var data = JSON.stringify(
                {
                    "nome": nome, 
                    "usuario": usuario, 
                    "senha": senha, 
                    "genero": genero, 
                    "data_nascimento": data_nascimento
                }
             );
        xhr.send(data); 
    } else {
        alert("Preencha todos os campos para continuar")
    }
    });       
});



