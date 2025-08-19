> [!important] Là lỗ hỏng xảy ra khi ứng dụng tham chiếu đến tài nguyên (object) như user_id; invoice_id; file.txt; ... mà không authorization. Cho phép hacker truy cập hoặc thao túng dữ liệu chỉ bằng cách đổi tham số. IDOR là lỗi logic nên các tool/script tự động thường không quét được. Cần quét thủ công.

# Cách dò

## Cách 1: URL

```Bash
https://example.com/profile?id=1
```

⇒ Đổi id=2

## Cách 2: POST method

Dùng Burp Suite hoặc curl

## Cách 3:

Dùng user này thử truy cập user khác

> **Kinh nghiệm**: Nên view source để xem có hidden ẩn nào không. Có thể chỉnh sửa code trực tiếp, đồng thời xem cả cookie.

---

# Ví dụ:

Thử truy cập user thường, thấy có nút đổi pass. View source thì phát hiện user thường có id=2. Thử đổi id=1 rồi đổi pass thì tài khoản được đổi là admin chứ không phải user.