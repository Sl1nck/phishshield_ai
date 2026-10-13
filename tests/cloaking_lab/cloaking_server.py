from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

class CloakingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        user_agent = self.headers.get("User-Agent", "").lower()
        
        # Detectar si es móvil o escritorio por el User-Agent
        is_mobile = "iphone" in user_agent or "android" in user_agent or "mobile" in user_agent
        
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        
        if is_mobile:
            html_content = """
            <html>
                <head><title>Actualización Crítica de Seguridad - Banco</title></head>
                <body>
                    <h1>Alerta de Seguridad: Su cuenta esta bloqueada</h1>
                    <p>Por favor ingrese sus credenciales para desbloquear el acceso inmediatamente.</p>
                    <form action="/login" method="POST">
                        <label>Usuario:</label><input type="text" name="username"><br>
                        <label>Contraseña:</label><input type="password" name="password"><br>
                        <button type="submit">Verificar Cuenta</button>
                    </form>
                    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </body>
            </html>
            """
        else:
            html_content = """
            <html>
                <head><title>Portal Corporativo Oficial</title></head>
                <body>
                    <h1>Bienvenido a nuestra web corporativa institucional.</h1>
                    <p>Todo en orden.</p>
                </body>
            </html>
            """
            
        self.wfile.write(html_content.encode("utf-8"))

def run_server(port=8080):
    server_address = ('127.0.0.1', port)
    # Usamos ThreadingHTTPServer para soportar peticiones paralelas de Playwright
    httpd = ThreadingHTTPServer(server_address, CloakingHandler)
    print(f"[+] Servidor local concurrente corriendo en http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido.")

if __name__ == "__main__":
    run_server()