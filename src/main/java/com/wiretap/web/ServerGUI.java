package com.wiretap.web;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Lightweight GUI window for WireTap server status
 */
public class ServerGUI {
    private final JFrame frame;
    private final int httpPort;
    private final int proxyPort;
    private final CountDownLatch closeLatch;
    private final AtomicBoolean isRunning;

    private JLabel statusLabel;
    private JLabel proxyStatusLabel;
    private JLabel uptimeLabel;

    private long startTime;

    public ServerGUI(int httpPort, int proxyPort) {
        this.httpPort = httpPort;
        this.proxyPort = proxyPort;
        this.closeLatch = new CountDownLatch(1);
        this.isRunning = new AtomicBoolean(true);
        this.startTime = System.currentTimeMillis();

        frame = createFrame();
        startUptimeTimer();
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

        // Header
        JPanel headerPanel = new JPanel();
        headerPanel.setBackground(new Color(70, 130, 180));
        JLabel titleLabel = new JLabel("WireTap Server");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 16));
        titleLabel.setForeground(Color.WHITE);
        headerPanel.add(titleLabel);
        frame.add(headerPanel, BorderLayout.NORTH);

        // Status panel
        JPanel statusPanel = new JPanel();
        statusPanel.setLayout(new GridLayout(4, 1, 5, 5));
        statusPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Server status
        statusLabel = new JLabel("🟢 Server running on http://localhost:" + httpPort);
        statusLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        statusPanel.add(statusLabel);

        // Proxy status
        proxyStatusLabel = new JLabel("🔄 Proxy listening on port " + proxyPort);
        proxyStatusLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        statusPanel.add(proxyStatusLabel);

        // Uptime
        uptimeLabel = new JLabel("⏱️  Uptime: 0s");
        uptimeLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        statusPanel.add(uptimeLabel);

        // Sessions info (placeholder)
        JLabel sessionsLabel = new JLabel("📊 Sessions: 0 active");
        sessionsLabel.setFont(new Font("Arial", Font.PLAIN, 12));
        statusPanel.add(sessionsLabel);

        frame.add(statusPanel, BorderLayout.CENTER);

        // Footer
        JPanel footerPanel = new JPanel();
        footerPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        JButton openBrowserButton = new JButton("Open Web Interface");
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

    private void startUptimeTimer() {
        Timer timer = new Timer(1000, e -> {
            if (isRunning.get()) {
                long uptime = (System.currentTimeMillis() - startTime) / 1000;
                long hours = uptime / 3600;
                long minutes = (uptime % 3600) / 60;
                long seconds = uptime % 60;

                String uptimeStr;
                if (hours > 0) {
                    uptimeStr = String.format("%dh %dm %ds", hours, minutes, seconds);
                } else if (minutes > 0) {
                    uptimeStr = String.format("%dm %ds", minutes, seconds);
                } else {
                    uptimeStr = String.format("%ds", seconds);
                }

                uptimeLabel.setText("⏱️  Uptime: " + uptimeStr);
            }
        });
        timer.start();
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

    public void updateProxyStatus(boolean isRunning, String status) {
        SwingUtilities.invokeLater(() -> {
            if (isRunning) {
                proxyStatusLabel.setText("🟢 Proxy running: " + status);
            } else {
                proxyStatusLabel.setText("🔴 Proxy stopped: " + status);
            }
        });
    }

    public void updateSessionCount(int count) {
        // This could be called from HttpApp to update session count
        SwingUtilities.invokeLater(() -> {
            // Update sessions label when we add it
        });
    }
}
