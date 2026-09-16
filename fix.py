import re
with open('src/protocol/http1/halmos_http1_manager.c', 'rb') as f:
    b = f.read()

# Replace binary null with string "\0"
b = b.replace(b"session->buffer[session->buf_len] = '\x00';", b"session->buffer[session->buf_len] = '\\0';")
# Replace actual newlines in strstr with \r\n\r\n
b = b.replace(b'strstr(session->buffer, "\r\n\r\n")', b'strstr(session->buffer, "\\r\\n\\r\\n")')
b = b.replace(b'strstr(session->buffer, "\n\n")', b'strstr(session->buffer, "\\r\\n\\r\\n")')

with open('src/protocol/http1/halmos_http1_manager.c', 'wb') as f:
    f.write(b)
