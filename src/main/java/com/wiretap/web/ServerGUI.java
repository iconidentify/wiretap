package com.wiretap.web;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Professional GUI window for WireTap server status and proxy monitoring
 */
public class ServerGUI {
    private final JFrame frame;
    private final int httpPort;
    private final int proxyPort;
    private final CountDownLatch closeLatch;
    private final AtomicBoolean isRunning;
    private HttpApp httpApp;

    // UI Components
    private JLabel statusIndicator;
    private JLabel proxyStatusIndicator;
    private JTextField proxyListenField;
    private JTextField proxyHostField;
    private JTextField proxyPortField;
    private JButton startProxyButton;
    private JButton stopProxyButton;
    private JLabel proxyStatusLed;


    public ServerGUI(int httpPort, int proxyPort) {
        this.httpPort = httpPort;
        this.proxyPort = proxyPort;
        this.closeLatch = new CountDownLatch(1);
        this.isRunning = new AtomicBoolean(true);

        frame = createFrame();
        frame.getContentPane().setBackground(new Color(236, 233, 216));
    }

    public void setHttpApp(HttpApp httpApp) {
        this.httpApp = httpApp;
    }

    private JFrame createFrame() {
        JFrame frame = new JFrame("WireTap - AOL Protocol Analyzer");
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                shutdown();
            }
        });

        frame.setLayout(new BorderLayout());
        frame.setResizable(false);

        // Native OS-style color scheme (mIRC circa 1996 style)
        Color primaryColor = new Color(0, 0, 128);       // Classic Windows blue
        Color successColor = new Color(0, 128, 0);       // Classic green
        Color warningColor = new Color(255, 165, 0);     // Orange
        Color grayColor = new Color(128, 128, 128);      // Classic gray
        Color darkGray = new Color(64, 64, 64);          // Dark gray
        Color lightGray = new Color(192, 192, 192);      // Light gray
        Color backgroundColor = new Color(236, 233, 216); // Classic Windows background
        Color surfaceColor = new Color(255, 255, 255);   // White surface

        // Header - Classic Windows-style
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(0, 0, 128)); // Classic Windows blue
        headerPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        JLabel titleLabel = new JLabel("WireTap");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 18));
        titleLabel.setForeground(Color.WHITE);

        statusIndicator = new JLabel("●");
        statusIndicator.setFont(new Font("Segoe UI", Font.BOLD, 14));
        statusIndicator.setForeground(successColor);

        headerPanel.add(titleLabel, BorderLayout.WEST);
        headerPanel.add(statusIndicator, BorderLayout.EAST);

        frame.add(headerPanel, BorderLayout.NORTH);

        // Main content panel
        JPanel contentPanel = new JPanel(new GridBagLayout());
        contentPanel.setBackground(backgroundColor);
        contentPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;

        // Proxy Control Section
        JPanel proxyControlPanel = createProxyControlPanel(primaryColor, grayColor);
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        contentPanel.add(proxyControlPanel, gbc);


        frame.add(contentPanel, BorderLayout.CENTER);

        // Footer - Simple Open Web Interface button
        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        footerPanel.setBackground(new Color(192, 192, 192));
        footerPanel.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));

        JButton openBrowserButton = createStyledButton("🌐 Open Web Interface", primaryColor);
        openBrowserButton.setFont(new Font("Segoe UI", Font.BOLD, 13));
        openBrowserButton.setForeground(Color.WHITE); // Ensure text is white and visible
        openBrowserButton.setPreferredSize(new Dimension(200, 40));
        openBrowserButton.addActionListener(e -> {
            try {
                Desktop.getDesktop().browse(java.net.URI.create("http://localhost:" + httpPort));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(frame, "Could not open browser: " + ex.getMessage());
            }
        });

        footerPanel.add(openBrowserButton);

        frame.add(footerPanel, BorderLayout.SOUTH);

        frame.pack();
        frame.setLocationRelativeTo(null); // Center on screen

        return frame;
    }

    private JPanel createStatusSection(String title, String value, Color indicatorColor) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(128, 128, 128), 1),
            BorderFactory.createEmptyBorder(8, 12, 8, 12)
        ));

        // Title with indicator
        JPanel titlePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        titlePanel.setBackground(Color.WHITE);

        JLabel indicator = new JLabel("●");
        indicator.setFont(new Font("Segoe UI", Font.BOLD, 12));
        indicator.setForeground(indicatorColor);

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        titleLabel.setForeground(Color.BLACK);

        titlePanel.add(indicator);
        titlePanel.add(titleLabel);

        // Value
        JLabel valueLabel = new JLabel(value);
        valueLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        valueLabel.setForeground(new Color(64, 64, 64));

        panel.add(titlePanel, BorderLayout.WEST);
        panel.add(valueLabel, BorderLayout.EAST);

        return panel;
    }

    private JPanel createProxyControlPanel(Color primaryColor, Color grayColor) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(128, 128, 128), 1),
            BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);

        // Title
        JLabel titleLabel = new JLabel("🔀 AOL Proxy Control");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        titleLabel.setForeground(Color.BLACK);
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 4;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(titleLabel, gbc);

        // Destination inputs
        JLabel destLabel = new JLabel("Destination:");
        destLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        gbc.gridy = 1; gbc.gridwidth = 1; gbc.weightx = 0;
        panel.add(destLabel, gbc);

        proxyHostField = new JTextField("127.0.0.1", 12);
        proxyHostField.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(proxyHostField, gbc);

        JLabel colonLabel = new JLabel(":");
        colonLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        gbc.gridx = 2; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        panel.add(colonLabel, gbc);

        proxyPortField = new JTextField("5190", 5);
        proxyPortField.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        gbc.gridx = 3; gbc.weightx = 0.3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(proxyPortField, gbc);

        // Listen port input
        JLabel listenLabel = new JLabel("Listen:");
        listenLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        gbc.gridy = 2; gbc.gridwidth = 1; gbc.weightx = 0; gbc.gridx = 0;
        panel.add(listenLabel, gbc);

        proxyListenField = new JTextField("5190", 5);
        proxyListenField.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        gbc.gridx = 1; gbc.weightx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(proxyListenField, gbc);

        // Control buttons - OS native style
        startProxyButton = createStyledButton("▶ Start Proxy", new Color(192, 192, 192));
        startProxyButton.setForeground(Color.BLACK);
        startProxyButton.addActionListener(e -> startProxy());

        stopProxyButton = createStyledButton("⏹ Stop Proxy", new Color(192, 192, 192));
        stopProxyButton.setForeground(Color.BLACK);
        stopProxyButton.setEnabled(false);
        stopProxyButton.addActionListener(e -> stopProxy());

        // Create LED status indicator
        proxyStatusLed = new JLabel("●");
        proxyStatusLed.setFont(new Font("MS Sans Serif", Font.BOLD, 14));
        proxyStatusLed.setForeground(new Color(128, 128, 128)); // Gray when stopped
        proxyStatusLed.setToolTipText("Proxy Status");

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttonPanel.setBackground(Color.WHITE);
        buttonPanel.add(proxyStatusLed);
        buttonPanel.add(startProxyButton);
        buttonPanel.add(stopProxyButton);

        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(12, 0, 0, 0);
        panel.add(buttonPanel, gbc);

        return panel;
    }


    private JButton createStyledButton(String text, Color bgColor) {
        JButton button = new JButton(text);
        button.setFont(new Font("MS Sans Serif", Font.BOLD, 11)); // Classic Windows font

        // Use black text for better readability
        button.setForeground(Color.BLACK);
        button.setBackground(bgColor);

        button.setOpaque(true); // Ensure background is painted
        button.setBorder(BorderFactory.createRaisedBevelBorder()); // Classic Windows button border
        button.setPreferredSize(new Dimension(110, 28)); // Slightly smaller, more proportional
        button.setFocusPainted(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        // Classic Windows-style hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBorder(BorderFactory.createLoweredBevelBorder());
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBorder(BorderFactory.createRaisedBevelBorder());
            }
        });

        return button;
    }


    public void show() {
        SwingUtilities.invokeLater(() -> {
            frame.setVisible(true);
        });
    }

    public void waitForClose() throws InterruptedException {
        closeLatch.await();
    }

    public void shutdown() {
        SwingUtilities.invokeLater(() -> {
            isRunning.set(false);
            frame.setVisible(false);
            frame.dispose();
            closeLatch.countDown();
        });
    }

    private void startProxy() {
        String listenPortText = proxyListenField.getText().trim();
        String host = proxyHostField.getText().trim();
        String portText = proxyPortField.getText().trim();

        if (listenPortText.isEmpty() || host.isEmpty() || portText.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Please enter listen port, host and port.", "Invalid Input", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            int listenPort = Integer.parseInt(listenPortText);
            int port = Integer.parseInt(portText);
            if (httpApp != null) {
                boolean success = httpApp.startProxy(listenPort, host, port);
                if (success) {
                    updateProxyUI(true, host + ":" + port);
                } else {
                    JOptionPane.showMessageDialog(frame, "Failed to start proxy. Please check the configuration.", "Proxy Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        } catch (NumberFormatException e) {
            JOptionPane.showMessageDialog(frame, "Ports must be valid numbers.", "Invalid Input", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void stopProxy() {
        if (httpApp != null) {
            boolean success = httpApp.stopProxy();
            if (success) {
                updateProxyUI(false, null);
            } else {
                JOptionPane.showMessageDialog(frame, "Failed to stop proxy.", "Proxy Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public void updateProxyUI(boolean isRunning, String destination) {
        SwingUtilities.invokeLater(() -> {
            startProxyButton.setEnabled(!isRunning);
            stopProxyButton.setEnabled(isRunning);

            // LED indicator for proxy status
            if (proxyStatusLed != null) {
                if (isRunning) {
                    proxyStatusLed.setForeground(new Color(34, 197, 94)); // Green when running
                    proxyStatusLed.setToolTipText("Proxy Running");
                } else {
                    proxyStatusLed.setForeground(new Color(128, 128, 128)); // Gray when stopped
                    proxyStatusLed.setToolTipText("Proxy Stopped");
                }
            }

            // Keep buttons with consistent neutral styling
            startProxyButton.setBackground(new Color(192, 192, 192));
            stopProxyButton.setBackground(new Color(192, 192, 192));

            // Update button text (keep consistent, readable text)
            startProxyButton.setText("▶ Start Proxy");
            stopProxyButton.setText("⏹ Stop Proxy");

            // Update main status indicator
            Color indicatorColor;
            if (isRunning && destination != null && !destination.isEmpty()) {
                indicatorColor = new Color(34, 197, 94); // Green-500
            } else if (isRunning) {
                indicatorColor = new Color(245, 158, 11); // Amber-500
            } else {
                indicatorColor = new Color(107, 114, 128); // Gray-500
            }
            statusIndicator.setForeground(indicatorColor);
        });
    }


    // Public methods for HttpApp to call
    public void updateProxyStatus(boolean isRunning, String destination) {
        updateProxyUI(isRunning, destination);
    }
}
