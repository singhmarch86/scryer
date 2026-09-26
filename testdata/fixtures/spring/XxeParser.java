package com.example.demo;

import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.w3c.dom.Document;

@Service
public class XxeParser {

    // Vulnerable: DocumentBuilderFactory built with its defaults, which
    // resolve external entities and DTDs (CWE-611/XXE). Parsing an
    // attacker-supplied XML body with this factory allows local file
    // disclosure and SSRF via a crafted DOCTYPE.
    public Document parse(@RequestBody byte[] xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml));
    }

    // Safe: external entities and DOCTYPE declarations are explicitly
    // disabled before parsing, per OWASP's XXE prevention cheat sheet.
    public Document parseSafe(@RequestBody byte[] xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml));
    }
}
