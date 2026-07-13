package logsentry;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Representa una regla de detección de seguridad.
 */
public class Regla {
    private final String nombre;
    private final String nivel;
    private final String patron;
    private final String mensaje;
    private Pattern compilado;

    public Regla(String nombre, String nivel, String patron, String mensaje) {
        this.nombre = nombre;
        this.nivel = nivel;
        this.patron = patron;
        this.mensaje = mensaje;
        this.compilado = Pattern.compile(patron, Pattern.CASE_INSENSITIVE);
    }

    public String getNombre() { return nombre; }
    public String getNivel() { return nivel; }
    public String getMensaje() { return mensaje; }

    public boolean coincide(String linea) {
        return compilado.matcher(linea).find();
    }
}
