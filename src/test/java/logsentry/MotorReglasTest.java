package logsentry;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests para el motor de reglas de LogSentry.
 */
public class MotorReglasTest {

    @Test
    public void testTotalReglas() {
        MotorReglas motor = new MotorReglas();
        assertTrue(motor.totalReglas() >= 8);
    }

    @Test
    public void testFiltroAll() {
        MotorReglas motor = new MotorReglas();
        assertEquals(motor.totalReglas(), motor.obtenerReglas("all").size());
    }

    @Test
    public void testFiltroBruteForce() {
        MotorReglas motor = new MotorReglas();
        assertEquals(1, motor.obtenerReglas("brute-force").size());
    }

    @Test
    public void testDeteccionSQLInjection() {
        MotorReglas motor = new MotorReglas();
        Regla sql = motor.obtenerReglas("sql-injection").get(0);
        assertTrue(sql.coincide("GET /api?id=1' OR 1=1--"));
        assertTrue(sql.coincide("'; DROP TABLE users;--"));
        assertFalse(sql.coincide("GET /index.html 200 OK"));
    }

    @Test
    public void testDeteccionXSS() {
        MotorReglas motor = new MotorReglas();
        Regla xss = motor.obtenerReglas("xss-attempt").get(0);
        assertTrue(xss.coincide("<script>alert('xss')</script>"));
        assertTrue(xss.coincide("onerror=alert(1)"));
        assertFalse(xss.coincide("GET /about 200 OK"));
    }

    @Test
    public void testDeteccionSSH() {
        MotorReglas motor = new MotorReglas();
        Regla ssh = motor.obtenerReglas("ssh-failed").get(0);
        assertTrue(ssh.coincide("Failed password for admin from 10.0.0.50 port 22 ssh2"));
        assertFalse(ssh.coincide("Login exitoso"));
    }

    @Test
    public void testDeteccionUserAgentSospechoso() {
        MotorReglas motor = new MotorReglas();
        Regla ua = motor.obtenerReglas("suspicious-ua").get(0);
        assertTrue(ua.coincide("User-Agent: sqlmap/1.7"));
        assertTrue(ua.coincide("UA: Nikto/2.1.6"));
        assertFalse(ua.coincide("UA: Mozilla/5.0"));
    }
}
