# Linux Security & System Investigation

> Практическая лабораторная работа по информационной безопасности: исследование Linux-системы, процессов, сетевых соединений и журналов.

## 1. Цель лабораторной

Цель работы — провести базовое исследование Linux-сервера с точки зрения информационной безопасности:

- определить конфигурацию серверной среды;
- исследовать пользователей, группы и привилегии;
- проверить работу `sudo`;
- проанализировать процессы и их иерархию;
- определить сетевые сервисы и связанные с ними процессы;
- исследовать файловые дескрипторы и сокеты;
- проанализировать SSH-журналы;
- исследовать HTTP-события Nginx;
- провести первичное расследование сетевой активности.

---

## 2. Lab Environment

### Система

| Параметр | Значение |
|---|---|
| Hostname | `phoenix-server` |
| ОС | Ubuntu 24.04.4 LTS |
| Kernel | Linux 6.8.0-139-generic |
| Архитектура | x86-64 |
| Виртуализация | Oracle VirtualBox |
| Текущий пользователь | `evgeni` |

### Сеть

| Интерфейс | Адрес | Назначение |
|---|---|---|
| `lo` | `127.0.0.1/8` | Loopback |
| `enp0s3` | `10.0.2.15/24` | NAT |
| `enp0s8` | `192.168.56.101/24` | Host-only |

### Используемые сервисы

- OpenSSH Server
- Nginx
- systemd
- systemd-journald

Nginx находится в состоянии `active (running)` и настроен на автоматический запуск (`enabled`).

---

## 3. Users & Access Control

### Пользователь `evgeni`

Команда:

```bash
id
```

показала:

```text
uid=1000(evgeni) gid=1000(evgeni) groups=1000(evgeni),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),101(lxd)
```

Пользователь входит в группу `sudo`.

Проверка:

```bash
sudo -l
```

результат:

```text
User evgeni may run the following commands:
    (ALL : ALL) ALL
```

Таким образом, `evgeni` обладает широкими административными полномочиями через `sudo`.

### Пользователь `testuser`

Проверка:

```bash
id testuser
```

результат:

```text
uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),100(users),1000(evgeni)
```

Ограничение `sudo`:

```bash
sudo -l -U testuser
```

результат:

```text
User testuser may run the following commands:
    (ALL) /usr/local/bin/show-hostname
```

### Security control — Least Privilege

`testuser` не получил полный административный доступ. Через `sudo` ему разрешена только конкретная команда:

```text
/usr/local/bin/show-hostname
```

Это демонстрирует принцип наименьших привилегий: пользователь получает только те административные полномочия, которые необходимы для выполнения конкретной задачи.

---

## 4. Process Investigation

### Nginx

Команда:

```bash
ps -o pid,ppid,user,cmd -C nginx
```

Результат:

```text
PID   PPID  USER      CMD
707     1   root      nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
710   707   www-data  nginx: worker process
711   707   www-data  nginx: worker process
```

Иерархия:

```text
systemd (PID 1)
      |
      +-- nginx master (PID 707, root)
             +-- nginx worker (PID 710, www-data)
             +-- nginx worker (PID 711, www-data)
```

### Security observation

Master-процесс Nginx работает от `root`, а worker-процессы — от `www-data`.

Это демонстрирует разделение привилегий между управляющим и рабочими процессами.

---

## 5. Network Investigation

Для анализа сетевых сервисов использовалась:

```bash
sudo ss -tlpn
```

Обнаружены TCP-сервисы:

| Сервис | Адрес | Порт | PID |
|---|---|---:|---|
| `systemd-resolved` | `127.0.0.54` / `127.0.0.53` | 53 | 450 |
| `sshd` | `0.0.0.0` / `[::]` | 22 | 996 |
| Nginx | `0.0.0.0` / `[::]` | 80 | 707/710/711 |

### SSH

```text
0.0.0.0:22
[::]:22
```

SSH-сервер принимает соединения по IPv4 и IPv6.

### HTTP

```text
0.0.0.0:80
[::]:80
```

Nginx принимает HTTP-соединения по IPv4 и IPv6.

В лабораторной была продемонстрирована цепочка:

```text
Сетевой порт
    ↓
Socket
    ↓
File Descriptor
    ↓
PID
    ↓
Process
    ↓
User
```

---

## 6. File Descriptor & Socket Investigation

Для Nginx PID `707`:

```bash
sudo ls -l /proc/707/fd/
```

были обнаружены:

```text
FD 2 -> /var/log/nginx/error.log
FD 3 -> /var/log/nginx/error.log
FD 4 -> /var/log/nginx/access.log
```

Также были обнаружены сетевые сокеты:

```text
FD 5 -> socket:[8356]
FD 6 -> socket:[8357]
FD 7 -> socket:[7589]
FD 8 -> socket:[7590]
FD 9 -> socket:[7591]
FD 10 -> socket:[7592]
```

Для SSH PID `996`:

```bash
sudo ls -l /proc/996/fd/
```

были обнаружены файловые дескрипторы, связанные с сокетами:

```text
FD 1 -> socket:[8867]
FD 2 -> socket:[8867]
FD 3 -> socket:[7233]
FD 4 -> socket:[7235]
```

Это позволяет использовать `/proc/<PID>/fd/` как источник дополнительной информации при расследовании процессов и сетевой активности.

---

## 7. SSH Log Analysis

Команда:

```bash
sudo journalctl -u ssh --since "today" --no-pager
```

показала успешную аутентификацию:

```text
Sep 29 08:02:39 phoenix-server sshd[997]: Accepted password for evgeni from 192.168.56.1 port 49279 ssh2
```

### Анализ события

| Параметр | Значение |
|---|---|
| Событие | Успешная аутентификация |
| Пользователь | `evgeni` |
| Источник | `192.168.56.1` |
| Исходный порт | `49279` |
| Протокол | SSH2 |
| Метод аутентификации | Password |

После успешной аутентификации была открыта пользовательская сессия:

```text
pam_unix(sshd:session): session opened for user evgeni(uid=1000) by evgeni(uid=0)
```

### Проверка неудачных аутентификаций

Использовалась команда:

```bash
sudo journalctl -u ssh --since "today" --no-pager | grep "Failed"
```

Результат — пустой.

Это означает, что в проверенном SSH-журнале за выбранный период записи, содержащие `Failed`, обнаружены не были.

Это не является доказательством отсутствия неудачных попыток за пределами проверенного журнала или периода.

---

## 8. Nginx Log Analysis

Изначально `access.log` не содержал записей.

Для создания контролируемого HTTP-события был выполнен запрос:

```bash
curl http://127.0.0.1
```

После этого в `/var/log/nginx/access.log` появилась запись:

```text
127.0.0.1 - - [29/Sep/2026:08:22:03 +0000] "GET / HTTP/1.1" 200 615 "-" "curl/8.5.0"
```

### Анализ события

| Поле | Значение |
|---|---|
| Source IP | `127.0.0.1` |
| Time | `29/Sep/2026 08:22:03 UTC` |
| Method | `GET` |
| URI | `/` |
| Protocol | HTTP/1.1 |
| Status | `200` |
| Response size | `615` |
| User-Agent | `curl/8.5.0` |

Событие соответствует ожидаемой активности лабораторной среды: запрос был намеренно создан с самого сервера через loopback-интерфейс.

---

## 9. Mini Incident Investigation

### Сценарий

На сервере обнаружен сетевой сервис. Требуется определить:

1. какой сервис работает;
2. какой процесс его обслуживает;
3. какой PID используется;
4. от какого пользователя запущен процесс;
5. какие события связаны с этим сервисом.

### Шаг 1 — сетевой сервис

Из `ss`:

```text
0.0.0.0:22 → sshd → PID 996
```

### Шаг 2 — процесс

Команда:

```bash
ps -o pid,ppid,user,cmd -p 996
```

результат:

```text
PID    PPID USER  CMD
996      1 root  sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
```

### Шаг 3 — журнал

В SSH-журнале обнаружено:

```text
sshd[997]: Accepted password for evgeni from 192.168.56.1 port 49279 ssh2
```

### Investigation chain

```text
TCP/22
   ↓
sshd
   ↓
PID 996
   ↓
PPID 1 / systemd
   ↓
USER root
   ↓
SSH session PID 997
   ↓
Successful authentication
   ↓
Source: 192.168.56.1
```

---

## 10. Security Findings

### Finding 1 — Privileged administrative account

`evgeni` обладает широкими административными полномочиями через `sudo`.

**Security consideration:** при компрометации учётной записи потенциально доступен широкий спектр административных действий.

**Control:** ограничивать административные права в соответствии с ролью и применять принцип наименьших привилегий.

### Finding 2 — Restricted sudo

`testuser` имеет через `sudo` доступ только к:

```text
/usr/local/bin/show-hostname
```

Это уменьшает объём доступных привилегированных действий.

### Finding 3 — Network exposure

На сервере доступны:

```text
TCP/22 — SSH
TCP/80 — HTTP
```

Сервисы слушают соответствующие IPv4/IPv6 wildcard-адреса.

В реальной инфраструктуре доступность таких сервисов должна соответствовать архитектуре и требованиям безопасности и дополнительно контролироваться сетевыми средствами защиты.

### Finding 4 — Logging

Доступны журналы:

```text
/var/log/nginx/access.log
/var/log/nginx/error.log
```

а также системный журнал SSH через `journalctl`.

Это позволяет проводить первичный анализ аутентификаций, HTTP-событий и ошибок сервисов.

---

## 11. Investigation Methodology

В лабораторной сформирована базовая последовательность первичного расследования:

```text
Обнаружение события
        ↓
Определение сетевого сервиса
        ↓
Socket / File Descriptor
        ↓
PID
        ↓
Process
        ↓
User
        ↓
Logs
        ↓
Контекст и ожидаемое поведение
        ↓
Security conclusion
```

Ключевой принцип:

> Отдельное событие само по себе ещё не является инцидентом. Необходимо сопоставлять источник, время, действие, процесс, пользователя и контекст системы.

---

## 12. Conclusion

В ходе лабораторной была исследована Linux-система `phoenix-server` и продемонстрированы базовые методы системного и сетевого анализа.

Исследованы:

- пользователи и группы;
- административные привилегии;
- ограниченный `sudo`;
- процессы и PPID;
- сетевые порты;
- sockets и file descriptors;
- SSH-аутентификация;
- Nginx HTTP-события;
- системные и прикладные журналы.

Практика показала, как перейти от отдельного сетевого или журналируемого события к конкретному процессу, пользователю и системному контексту.

**Skills demonstrated:**

- Linux user and group management
- Least Privilege / restricted sudo
- Process and PPID analysis
- Network socket investigation
- `/proc` inspection
- SSH log analysis
- Nginx log analysis
- Command-line log analysis
- Initial security investigation methodology

---

## Screenshots

Скриншоты ключевых этапов лаборатории можно добавить в дальнейшем.
