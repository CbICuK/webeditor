$(document).ready(function () {
    function validatePassword() {
        const password = $('#password').val();
        const confirmPassword = $('#confirm_password').val();
        const messageBox = $('#messageBox');
        const registerButton = $('#registerButton');

        const minLength = 8;
        const patterns = [
            /[A-Z]/,  // Заглавные буквы
            /[a-z]/,  // Строчные буквы
            /\d/,     // Цифры
            /[!@#$%^&*(),.?":{}|<>]/ // Специальные символы
        ];
        const matchCount = patterns.reduce((count, pattern) => count + (pattern.test(password) ? 1 : 0), 0);
        const isPasswordValid = password.length >= minLength && matchCount >= 3;

        let messages = [];

        // Проверка сложности пароля
        if (password.length > 0 && !isPasswordValid) {
            messages.push('<div id="not-strong">- Пароль должен содержать минимум 8 символов и 3 из 4 групп символов: заглавные буквы, строчные буквы, цифры или спецсимволы.</div>');
            $('#password').removeClass('valid').addClass('invalid');
        } else if (password.length > 0) {
            $('#password').removeClass('invalid').addClass('valid');
        } else {
            $('#password').removeClass('valid invalid');
        }

        // Проверка совпадения паролей
        if (confirmPassword.length > 0) {
            if (password !== confirmPassword) {
                messages.push('<div id="not-length">- Пароли не совпадают.</div>');
                $('#confirm_password').removeClass('valid').addClass('invalid');
            } else {
                $('#confirm_password').removeClass('invalid').addClass('valid');
            }
        } else {
            $('#confirm_password').removeClass('valid invalid');
        }

        // Отображение сообщений в одном поле
        if (messages.length > 0) {
            messageBox.html(messages.join('')).show();
        } else {
            $("#not-length").hide();
            $("#not-strong").hide();
        }

        // Разблокировка кнопки, если всё корректно
        registerButton.prop('disabled', !(isPasswordValid && password === confirmPassword));
    }

    $('#registerForm').on('submit', function (event) {
        event.preventDefault(); // Предотвращаем стандартную отправку формы

        // Собираем данные формы
        const formData = $(this).serialize();

        // Отправляем AJAX-запрос на сервер
        $.ajax({
            url: '/register', // URL для отправки данных
            type: 'POST',
            data: formData,
            success: function (response) {
                if (response.success) {
                    $('#messageBox').text(response.message).css('color', 'green');
                } else {
                    $('#messageBox').text(response.responseJSON.message).css('color', 'red');
                }
            },
            error: function (xhr, status, error) {
                $('#messageBox').text(xhr.responseJSON.message).css('color', 'red');
            }
        });
    });

    // Отслеживание ввода в полях
    $('#password, #confirm_password').on('input', validatePassword);
});
