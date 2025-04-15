$(document).ready(function () {
    $('#loginForm').on('submit', function (e) {
        e.preventDefault(); // Останавливаем стандартное отправление формы

        const username = $('#username').val().trim();
        const password = $('#password').val().trim();

        // Простая валидация на стороне клиента
        if (!username || !password) {
            $('#errorMessage').text('Please fill out both fields.').show();
            return;
        }

        // Асинхронная отправка данных на сервер
        $.ajax({
            url: '/login',
            method: 'POST',
            contentType: 'application/x-www-form-urlencoded',
            data: {
                username: username,
                password: password
            },
            success: function (response) {
                var link = $(response).find('redirect_url').first().text();
                // Если логин успешен, перенаправляем пользователя
                if (link) {
                    // Перенаправляем на защищённую страницу
                    window.location.href = link;
                }
            },
            error: function (xhr) {
                console.log(xhr);
                if (xhr.responseJSON && xhr.responseJSON.status === "error") {
                    $('#errorMessage').text(xhr.responseJSON.message).show();
                } else {
                    $('#errorMessage').text('An unexpected error occurred.').show();
                }
            }
        });
    });
    // Показ модального окна для восстановления пароля
    $('#forgotPasswordLink').click(function (e) {
        e.preventDefault();
        $("input#email.form-control").val("");
        $('#recoverPasswordModal').css('display', 'flex');
    });

    // Скрытие модального окна при нажатии на отмену
    $('#cancelRecoverPassword').click(function () {
        $('#recoverPasswordModal').hide();
    });

    // Обработка формы восстановления пароля
    $('#recoverPasswordForm').submit(function (e) {
        e.preventDefault();
        var email = $('#email').val();

        $.ajax({
            url: '/recover_password',
            method: 'POST',
            data: { email: email },
            success: function (response) {
                alert(response.message);
                $('#recoverPasswordModal').hide();
            },
            error: function (xhr) {
                var errorMessage = xhr.responseJSON ? xhr.responseJSON.message : 'Произошла ошибка при отправке запроса.';
                alert(errorMessage);
            }
        });
    });

    $("#registerButton").click(function () {
        $(this).fadeOut(200).fadeIn(200, function () {
            window.location.href = "/register";
        });
    });


});
