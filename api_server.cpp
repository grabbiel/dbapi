#include "include/Logger.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8443 // Different from your main web server
#define BUFFER_SIZE 4096
#define CLIENT_IP                                                              \
  "YOUR_LOCAL_MACHINE_IP" // Replace with your local machine's public IP

// Simplified client check - only allows your IP
bool is_allowed_client(const struct sockaddr_in &client_addr) {
  char client_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
  std::string ip_str = client_ip;

  bool ip_allowed = (ip_str == CLIENT_IP);

  LOG_INFO("Connection attempt from IP: ", ip_str, " - ",
           ip_allowed ? "allowed" : "denied");

  return ip_allowed;
}

// Sample handler for database content
void handle_get_content(SSL *ssl, std::string &response) {
  // Example JSON response
  response += "{\n";
  response += "  \"status\": \"success\",\n";
  response += "  \"data\": {\n";
  response += "    \"content\": [\n";
  response += "      {\n";
  response += "        \"id\": 1,\n";
  response += "        \"title\": \"Sample Content\",\n";
  response += "        \"status\": \"published\"\n";
  response += "      }\n";
  response += "    ]\n";
  response += "  }\n";
  response += "}";

  SSL_write(ssl, response.c_str(), response.length());
  LOG_INFO("Processed GET request for content");
}

// comment that needs to be here to deploy idk why ok bye
void handle_get(SSL *ssl, const std::string &req) {
  size_t path_start = req.find(" ") + 1;
  size_t path_end = req.find(" ", path_start);
  std::string path = req.substr(path_start, path_end - path_start);

  std::string response = "HTTP/1.1 200 OK\r\n";
  response += "Content-Type: application/json\r\n"; // Changed to JSON
  response += "Connection: close\r\n\r\n";

  // API endpoints
  if (path == "/api/content") {
    handle_get_content(ssl, response);
  }
  // Add more API endpoints as needed
  else {
    response = "HTTP/1.1 404 Not Found\r\n";
    response += "Content-Type: application/json\r\n";
    response += "Connection: close\r\n\r\n";
    response += "{\"error\": \"Endpoint not found\"}";
    SSL_write(ssl, response.c_str(), response.length());
  }
}

void handle_request(SSL *ssl, const char *request,
                    const struct sockaddr_in &client_addr) {
  if (!is_allowed_client(client_addr)) {
    std::string response = "HTTP/1.1 403 Forbidden\r\n";
    response += "Content-Type: application/json\r\n";
    response += "Connection: close\r\n\r\n";
    response += "{\"error\": \"Access denied: Unauthorized IP address\"}";
    SSL_write(ssl, response.c_str(), response.length());
    LOG_WARNING("Blocked unauthorized request from ",
                inet_ntoa(client_addr.sin_addr));
    return;
  }

  std::string req(request);
  LOG_DEBUG("Received request: ", request);

  if (req.find("GET") == 0) {
    handle_get(ssl, req);
  } else {
    std::string response = "HTTP/1.1 405 Method Not Allowed\r\n";
    response += "Content-Type: application/json\r\n";
    response += "Connection: close\r\n\r\n";
    response += "{\"error\": \"Method not allowed\"}";
    SSL_write(ssl, response.c_str(), response.length());
    LOG_WARNING("Received unsupported request method");
  }
}

SSL_CTX *create_context() {
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = TLS_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

void configure_context(SSL_CTX *ctx, const char *cert_path,
                       const char *key_path) {
  if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}
int main() {
  Logger::getInstance().setLogFile("/var/log/api-server.log");
  Logger::getInstance().setLogLevel(LogLevel::INFO);

  LOG_INFO("API Server starting initialization...");

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX *ctx = create_context();
  configure_context(ctx,
                    "/etc/letsencrypt/live/server.grabbiel.com/fullchain.pem",
                    "/etc/letsencrypt/live/server.grabbiel.com/privkey.pem");

  int server_fd;
  struct sockaddr_in address;
  int opt = 1;
  char buffer[BUFFER_SIZE] = {0};

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    LOG_FATAL("Socket creation failed: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    LOG_ERROR("Failed to set socket options: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    LOG_FATAL("Bind failed: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0) {
    LOG_FATAL("Listen failed: ", strerror(errno));
    exit(EXIT_FAILURE);
  }

  LOG_INFO("API Server listening on port ", PORT);

  while (1) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int new_socket;

    if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr,
                             &client_len)) < 0) {
      LOG_ERROR("Accept failed: ", strerror(errno));
      continue; // Continue instead of exit to keep server running
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);

    if (SSL_accept(ssl) <= 0) {
      LOG_ERROR("SSL accept failed");
      ERR_print_errors_fp(stderr);
    } else {
      memset(buffer, 0, BUFFER_SIZE);
      int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

      if (bytes > 0) {
        buffer[bytes] = '\0';
        handle_request(ssl, buffer, client_addr);
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
  }

  SSL_CTX_free(ctx);
  close(server_fd);
  EVP_cleanup();

  return 0;
}
