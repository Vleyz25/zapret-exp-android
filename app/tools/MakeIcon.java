import java.awt.*;
import java.awt.geom.*;
import java.awt.image.BufferedImage;
import java.io.File;
import javax.imageio.ImageIO;

/**
 * Генератор иконки приложения: без внешних файлов и без интернета.
 * Использование: java MakeIcon <путь.png> <размер>
 */
public class MakeIcon {
    public static void main(String[] args) throws Exception {
        String out = args.length > 0 ? args[0] : "ic_launcher.png";
        int s = args.length > 1 ? Integer.parseInt(args[1]) : 192;

        BufferedImage img = new BufferedImage(s, s, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // фон: тёмно-синий скруглённый квадрат
        g.setPaint(new GradientPaint(0, 0, new Color(0x14203a), s, s, new Color(0x0b1224)));
        g.fill(new RoundRectangle2D.Float(0, 0, s, s, s * 0.22f, s * 0.22f));

        // знак «запрет»: круг с перечёркнутой линией
        float m = s * 0.20f;
        Ellipse2D ring = new Ellipse2D.Float(m, m * 0.75f, s - 2 * m, s - 2 * m * 0.75f - s * 0.16f);
        g.setColor(Color.WHITE);
        g.setStroke(new BasicStroke(s * 0.055f));
        g.draw(ring);
        Rectangle2D bar = new Rectangle2D.Float(
                (float) (ring.getX() + ring.getWidth() * 0.16f),
                (float) (ring.getY() + ring.getHeight() * 0.44f),
                (float) (ring.getWidth() * 0.68f),
                s * 0.055f);
        Shape rotated = AffineTransform.getRotateInstance(Math.toRadians(-45),
                bar.getCenterX(), bar.getCenterY()).createTransformedShape(bar);
        g.fill(rotated);

        // подпись EXP
        g.setFont(new Font("SansSerif", Font.BOLD, (int) (s * 0.14f)));
        FontMetrics fm = g.getFontMetrics();
        String text = "EXP";
        int w = fm.stringWidth(text);
        g.setColor(new Color(0x7fd0ff));
        g.drawString(text, (s - w) / 2, (int) (s * 0.94f));
        g.dispose();

        File f = new File(out);
        if (f.getParentFile() != null) f.getParentFile().mkdirs();
        ImageIO.write(img, "png", f);
        System.out.println("иконка: " + f.getAbsolutePath() + " " + s + "x" + s);
    }
}
