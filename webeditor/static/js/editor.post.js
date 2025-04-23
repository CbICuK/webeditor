let l = $("#ip-input").val().length
let f = false;

const socket = io();

if (l === 0) {
    f = true;
}
function validateIP(ip) {
    const regex =
        /^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;
    return regex.test(ip);
}

function addIP(ip) {
    if (!validateIP(ip)) {
        $("#error-message").text("Некорректный IP-адрес").show();
        return;
    }
    if ($(".ip-box").filter(function () {
        return $(this).text() === ip;
    }).length > 0) {
        $("#error-message").text("Дубликаты IP-адресов запрещены").show();
        return;
    }
    $("#error-message").hide();
    const ipBox = $('<div class="ip-box"></div>').text(ip);
    ipBox.on('click', function () {
        //$(this).remove();
        //togglePlaceholder();
        deselectAll();
        $(this).addClass("selected");
    });
    $("#ip-input").before(ipBox);
    $("#ip-input").val("");
    togglePlaceholder();
    bindIPBoxEvents();
}

function togglePlaceholder() {
    if ($(".ip-box").length === 0 && $("#ip-input").val() === "") {
        $("#placeholder").show();
    } else {
        $("#placeholder").hide();
    }
}

let lastSecectedIndex = null;

function deselectAll() {
    $(".ip-box").removeClass("selected");
}

function deleteSelectedIP() {
    const selected = $(".ip-box.selected");
    if (selected.length > 0) {
        selected.remove();
        togglePlaceholder();
    }
}

function bindIPBoxEvents() {
    $(".ip-box").off("click").on("click", function (e) {
        const allBoxes = $(".ip-box");
        const clickedIndex = allBoxes.index(this);
        if (e.shiftKey && lastSecectedIndex !== null) {
            const start = Math.min(lastSecectedIndex, clickedIndex);
            const end = Math.max(lastSecectedIndex, clickedIndex);

            for (let i = start; i <= end; i++) {
                $(allBoxes[i]).addClass("selected");
            }
        } else {
            if (!e.ctrlKey && !e.metaKey) {
                if ($(this).hasClass("selected")) {
                    deselectAll();
                    lastSecectedIndex = 0;
                } else {
                    deselectAll();
                    $(this).toggleClass("selected");
                    lastSecectedIndex = clickedIndex;
                }
            } else {
                $(this).toggleClass("selected");
                lastSecectedIndex = clickedIndex;
            }
        }
        //deselectAll();
        //$(this).addClass("selected");
    });
}

function sortIPs() {
    deselectAll();
    const ipBoxes = Array.from($("#ip-container .ip-box"));

    // Парсим IP, превращаем в массив чисел для сортировки
    const sorted = ipBoxes.sort((a, b) => {
        const ipA = a.textContent.trim().split('.').map(num => parseInt(num));
        const ipB = b.textContent.trim().split('.').map(num => parseInt(num));

        for (let i = 0; i < 4; i++) {
            if (ipA[i] !== ipB[i]) return ipA[i] - ipB[i];
        }
        return 0;
    });
    
    // Очистка и повторное добавление отсортированных элементов
    $("#ip-container .ip-box").remove();
    if ($("#ip-container").hasClass("sorted")) {
        $("#ip-container").removeClass("sorted");
        $("#ip-container").toggleClass("sorted-backwards");
        sorted.forEach(box => $("#ip-container").prepend(box));
    } else {
        if ($("#ip-container").hasClass("sorted-backwards")) {
            $("#ip-container").removeClass("sorted-backwards");
        }
        $("#ip-container").toggleClass("sorted");
        sorted.reverse().forEach(box => $("#ip-container").prepend(box));
    }    
    bindIPBoxEvents();
}

function reload_list() {
    let ipInput = $("#ip-input");

    $.ajax({
        url: '/get_ip_list',
        method: 'GET',
        success: function (response) {
            if (response && response.ip_list) {
                $("#ip-container").empty();
                response.ip_list.forEach(function (ip) {
                    const ipBox = $('<div class="ip-box"></div>').text(ip);
                    $("#ip-container").append(ipBox);
                    bindIPBoxEvents();
                });
                $("#ip-container").append(ipInput);
                ipInput.val('');
                togglePlaceholder();
            }
        },
        error: function () {
            alert("Ошибка загрузки списка IP-адресов.");
        }
    });
}

// Обработчик для ввода данных в поле input
$("#ip-container").on("input", '#ip-input', function () {
    $("#error-message").hide(); // Прячем ошибку при изменении текста
    let inputText = $(this).val();

    // Разделяем строку на IP-адреса по пробелам и символам новой строки
    let ipAddresses = inputText.split(/\s+|\n+/);

    togglePlaceholder();
});

$("#ip-container").on("keyup", "#ip-input", function (event) {
    let ip = $(this).val().trim();
    if (event.key === "Enter" && ip) {
        addIP(ip);
        $(this).val(""); // Очищаем поле после добавления
    } else if ((event.key === " " || event.key === "Enter") && ip) {
        let ipAddresses = ip.split(/\s+|\n+/);
        ipAddresses.forEach(function (address) {
            address = address.trim();
            if (address) {
                addIP(address);
            }
        });

        $(this).val(""); // Очищаем поле ввода после обработки
    }
    togglePlaceholder();
});

$("#ip-container").on("keydown", "#ip-input", function (event) {
    if (event.key === "Backspace" && $(this).val() === "") {
        let lastIPBox = $(".ip-box").last();
        if (lastIPBox.length) {
            $(this).val(lastIPBox.text());
            lastIPBox.remove();
        }
    }
});

$("#ip-container").on("focus", "#ip-input", function (event) {
    deselectAll();
});

$(".container").on("click", "#sort-button", function () {
    sortIPs();
});

$(".container").on("click", "#save-button", function () {
    let ipList = $(".ip-box").map(function () {
        return $(this).text();
    }).get();
    $.ajax({
        url: '/save_ip_list',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            ip_list: ipList,
            sid: socket.id
        }),
        success: function () {
            //console.log("IP-адреса сохранены успешно!");
            alert("IP-адреса сохранены успешно!");
        },
        error: function (response) {
            if (response.status == 403) {
                alert("Вы не авторизованы или сессия истекла. Войдите в систему.");
            } else {
                alert("Ошибка сохранения. Попробуйте снова.");
            }
            
        }
    });
});

$(".container").on("click", "#logout-button", function () {
    $.ajax({
        url: '/logout',
        method: 'GET',
        success: function () {
            window.location.href = '/login';
        },
        error: function () {
            alert('Ошибка при выходе. Повторите попытку.');
        }
    });
});

$(".container").on("click", "#cancel-button", reload_list);

$("#reload").on("click", function() {
    $('#reload-modal').hide();
    $('#error-message').hide();
    reload_list();
});

$("#dismiss").on("click", function() {
    $('#reload-modal').hide();
    $('#error-message').text("Вы продолжаете редактировать устаревшую версию списка.").show();
});

$(document).on("keydown", function (event) {
    // Удаление по Delete / Backspace
    if (event.key === "Backspace" || event.key === "Delete") {
        deleteSelectedIP();
    }

    // Копирование по Ctrl+C / Cmd+C
    if ((event.ctrlKey || event.metaKey) && (event.key.toLowerCase() === "c" || event.key.toLowerCase() === "с")) {
        const selectedIPs = $(".ip-box.selected").map(function () {
            return $(this).text();
        }).get().join('\n');

        if (selectedIPs) {
            navigator.clipboard.writeText(selectedIPs).then(function () {
                console.log("IP-адреса скопированы: ", selectedIPs);
            }).catch(function (err) {
                alert("Ошибка при копировании: " + err);
            });
        }
    }

    if ((event.ctrlKey || event.metaKey) && (event.key.toLowerCase() === "x" || event.key.toLowerCase() === "ч")) {
        const selectedIPs = $(".ip-box.selected").map(function () {
            return $(this).text();
        }).get().join('\n');

        if (selectedIPs) {
            navigator.clipboard.writeText(selectedIPs).then(function () {
                console.log("IP-адреса скопированы: ", selectedIPs);
            }).catch(function (err) {
                alert("Ошибка при копировании: " + err);
            });
        }
        $(".ip-box.selected").remove();
    }

});

$(document).ready(function () {
    bindIPBoxEvents();
});

socket.on('updated', (username) => {
    $("#updated-user").text(username);
    $('#reload-modal').css('display', 'flex');
});

togglePlaceholder();

