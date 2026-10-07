from phishshield.scraper.parser import DOMParser, ParsedDOM


def test_dom_parser_standard_extraction():
    html = """
    <html>
        <head><title>Página de Login Ejemplo</title></head>
        <body>
            <form action="/login.php" method="POST">
                <input name="username" type="text" placeholder="Usuario">
                <input name="password" type="password" placeholder="Contraseña">
            </form>
            <a href="https://example.com/terms">Términos</a>
            <iframe src="https://malicious-domain.com/embed"></iframe>
            <script>console.log('test');</script>
            <p>Texto visible de la página.</p>
        </body>
    </html>
    """

    parser = DOMParser(html)
    parsed = parser.parse()

    assert isinstance(parsed, ParsedDOM)
    assert parsed.title == "Página de Login Ejemplo"
    assert parsed.form_actions == ["/login.php"]
    assert len(parsed.input_fields) == 2
    assert parsed.has_password_field is True
    assert parsed.iframes == ["https://malicious-domain.com/embed"]
    assert parsed.links == ["https://example.com/terms"]
    assert "Texto visible de la página." in parsed.clean_text
    assert "console.log" not in parsed.clean_text  # Scripts deben ser descompuestos


def test_dom_parser_handles_empty_or_none_html():
    parser_none = DOMParser(None)
    parsed_none = parser_none.parse()
    assert parsed_none.title == ""
    assert parsed_none.has_password_field is False
    assert parsed_none.links == []

    parser_empty = DOMParser("")
    parsed_empty = parser_empty.parse()
    assert parsed_empty.title == ""
    assert parsed_empty.has_password_field is False


def test_dom_parser_without_password_field():
    html = '<html><head><title>Blog</title></head><body><input type="search"></body></html>'
    parser = DOMParser(html)
    parsed = parser.parse()

    assert parsed.has_password_field is False
    assert parsed.text_content != ""