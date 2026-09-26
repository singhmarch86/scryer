package com.example.demo;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;

@Service
public class InsecureDeserializationService {

    // Vulnerable: deserializes a byte array taken directly from the request
    // body with Java's native ObjectInputStream (CWE-502). Untrusted input
    // reaching readObject() is a classic RCE gadget-chain vector (ysoserial
    // et al.), regardless of what the resulting object is used for.
    public Object handle(@RequestBody byte[] payload) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        return ois.readObject();
    }

    // Not attacker-controlled: deserializes a fixed, server-controlled byte
    // array, not anything derived from the request. Note that Semgrep's own
    // registry rule (java.lang.security.audit.object-deserialization)
    // flags this call too, with no taint distinction — a deliberately
    // blanket "any native ObjectInputStream.readObject() is risky" stance,
    // since a gadget-chain exploit doesn't need the *content* to be
    // attacker-controlled, only the classpath. Scryer doesn't add a rule
    // here since the registry already covers it (see docs/FINDINGS.md #3).
    public Object handleFixed() throws IOException, ClassNotFoundException {
        byte[] trusted = loadTrustedSnapshot();
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(trusted));
        return ois.readObject();
    }

    private byte[] loadTrustedSnapshot() {
        return new byte[0];
    }
}
