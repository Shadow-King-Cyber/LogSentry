package logsentry;

/**
 * Representa una alerta generada por el analizador.
 */
public class Alerta {
    private final int linea;
    private final String nivel;
    private final String regla;
    private final String mensaje;
    private final String contenido;

    public Alerta(int linea, String nivel, String regla, String mensaje, String contenido) {
        this.linea = linea;
        this.nivel = nivel;
        this.regla = regla;
        this.mensaje = mensaje;
        this.contenido = contenido;
    }

    public int getLinea() { return linea; }
    public String getNivel() { return nivel; }
    public String getRegla() { return regla; }
    public String getMensaje() { return mensaje; }
    public String getContenido() { return contenido; }

    @Override
    public String toString() {
        return String.format("[%s] Línea %d (%s): %s", nivel.toUpperCase(), linea, regla, mensaje);
    }
}
