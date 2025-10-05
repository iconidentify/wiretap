package com.wiretap.tools;

import com.wiretap.core.WireTapLog;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses fdomanual1.txt and fdomanual2.txt and emits:
 *  - protocol/protocols.json
 *  - protocol/atoms.jsonl
 *  - protocol/tokens.json
 *
 * Heuristics-based extractor; tolerant of imperfect formatting in OCR'd text.
 */
public final class ProtocolIndexBuilder {
    private static final Pattern CHAPTER_PROTOCOL = Pattern.compile("^Chapter\\s+\\d+:\\s+(.+?)\\s+Protocol(.*)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROTOCOL_ID = Pattern.compile("\\(protocol ID\\s+(\\d+)\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern PROTOCOL_TAG_PARENS = Pattern.compile("\\((?:protocol\\s+)?([A-Z]{2,5})\\)" );
    private static final Pattern ATOM_LINE = Pattern.compile("^atom\\$([a-zA-Z0-9_]+)(.*)$");
    private static final Pattern ATOM_SIG = Pattern.compile("^atom\\$([a-zA-Z0-9_]+)\\s+(.+)$");
    private static final Pattern TOKEN_QUOTED = Pattern.compile("token(?:\\s+of)?\\s+'([^']{2})'", Pattern.CASE_INSENSITIVE);
    private static final Pattern TOKEN_OF = Pattern.compile("routing token of\\s+([A-Za-z0-9#\\$%&@*+\u002D/=\\?^_\\|~]{2})\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern TOKEN_PAIRED = Pattern.compile("\\b([A-Za-z0-9#\\$%&@*+\u002D/=\\?^_\\|~]{2})\\s+token\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern HOST_TO_CLIENT = Pattern.compile("host-to-client", Pattern.CASE_INSENSITIVE);
    private static final Pattern CLIENT_TO_HOST = Pattern.compile("client-to-host", Pattern.CASE_INSENSITIVE);

    private static final Map<String, String> ATOM_PREFIX_TO_PROTOCOL = Map.ofEntries(
            Map.entry("adp_", "ADP"),
            Map.entry("act_", "ACT"),
            Map.entry("buf_", "BUF"),
            Map.entry("ccl_", "CCL"),
            Map.entry("chat_", "CHAT"),
            Map.entry("cm_", "CM"),
            Map.entry("de_", "DE"),
            Map.entry("fm_", "FM"),
            Map.entry("hfs_", "HFS"),
            Map.entry("idb_", "IDB"),
            Map.entry("lm_", "LM"),
            Map.entry("man_", "MAN"),
            Map.entry("mat_", "MAT"),
            Map.entry("p3_", "P3"),
            Map.entry("sm_", "SM"),
            Map.entry("uni_", "UNI"),
            Map.entry("vid_", "VID"),
            Map.entry("www_", "WWW"),
            Map.entry("xfer_", "XFER")
    );

    private static final class ProtocolInfo {
        String name;
        String tag;
        Integer id;
        String summary;
        String source;
    }

    private static final class AtomInfo {
        String name;
        String protocol;
        String signature;
        String synopsis;
        String source;
    }

    private static final class TokenInfo {
        String token;
        String protocol;
        List<String> examples = new ArrayList<>();
        boolean hostToClient;
        boolean clientToHost;
        String source;
    }

    public static void main(String[] args) throws Exception {
        Path root = Paths.get("");
        Path protoDir = root.resolve("protocol");
        Path f1 = protoDir.resolve("fdomanual1.txt");
        Path f2 = protoDir.resolve("fdomanual2.txt");
        if (args.length >= 1) {
            f1 = Paths.get(args[0]);
        }
        if (args.length >= 2) {
            f2 = Paths.get(args[1]);
        }

        Map<String, ProtocolInfo> protocols = new LinkedHashMap<>();
        List<AtomInfo> atoms = new ArrayList<>();
        Map<String, TokenInfo> tokens = new TreeMap<>();

        parseManual(f1, protocols, atoms, tokens);
        parseManual(f2, protocols, atoms, tokens);

        // Enrich tokens from tokens_2001.txt if present
        Path tokens2001 = protoDir.resolve("tokens_2001.txt");
        if (Files.exists(tokens2001)) {
            parseTokens2001(tokens2001, tokens);
        }

        // sort atoms by protocol then name
        atoms.sort(Comparator.comparing((AtomInfo a) -> a.protocol == null ? "" : a.protocol)
                .thenComparing(a -> a.name));

        // Optional: merge existing curated tokens.json to preserve manual edits
        Path existingTokens = protoDir.resolve("tokens.json");
        if (Files.exists(existingTokens)) {
            try {
                String json = Files.readString(existingTokens);
                Map<String,Object> cur = parseSimpleJsonMap(json);
                for (Map.Entry<String,Object> e : cur.entrySet()) {
                    tokens.putIfAbsent(e.getKey(), toTokenInfo(e.getKey(), (Map<String,Object>) e.getValue()));
                }
            } catch (Exception ignored) {}
        }

        // write outputs
        writeProtocols(protoDir.resolve("protocols.json"), protocols.values());
        writeAtoms(protoDir.resolve("atoms.jsonl"), atoms);
        writeTokens(protoDir.resolve("tokens.json"), tokens);

        WireTapLog.debug("Wrote: " + protoDir.resolve("protocols.json").toAbsolutePath());
        WireTapLog.debug("Wrote: " + protoDir.resolve("atoms.jsonl").toAbsolutePath());
        WireTapLog.debug("Wrote: " + protoDir.resolve("tokens.json").toAbsolutePath());
    }

    private static void parseTokens2001(Path file, Map<String, TokenInfo> tokens) throws IOException {
        // Format is varied; heuristic line parser: `<tk>  <description>  <module>`
        Pattern line = Pattern.compile("^\\s*([A-Za-z0-9#\\$%&@*+\u002D/=\\?^_\\|~]{2})\\s+(.+?)\\s{2,}([A-Za-z0-9_\u002D]+)\\s*$");
        try (BufferedReader br = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String s; int ln = 0;
            while ((s = br.readLine()) != null) {
                ln++;
                java.util.regex.Matcher m = line.matcher(s);
                if (!m.find()) continue;
                String tk = m.group(1);
                if (tk == null || tk.length() != 2) continue;
                String desc = m.group(2).trim();
                String module = m.group(3).trim();
                TokenInfo ti = tokens.computeIfAbsent(tk, k -> new TokenInfo());
                ti.token = tk;
                if (ti.examples.size() < 1) ti.examples.add(desc);
                if (ti.source == null) ti.source = file.getFileName() + ":" + ln;
                // Try to infer protocol tag from module names
                String prot = inferProtocolFromModule(module);
                if (ti.protocol == null && prot != null) ti.protocol = prot;
            }
        }
    }

    private static String inferProtocolFromModule(String module) {
        String m = module.toLowerCase(Locale.ROOT);
        if (m.contains("chat")) return "CHAT";
        if (m.contains("hfs") || m.contains("designer")) return "HFS";
        if (m.contains("vid")) return "VID";
        if (m.contains("xfer") || m.contains("file")) return "XFER";
        if (m.contains("p3")) return "P3";
        if (m.contains("adp")) return "ADP";
        if (m.contains("www")) return "WWW";
        if (m.contains("fm")) return "FM";
        if (m.contains("sm")) return "SM";
        if (m.contains("mat")) return "MAT";
        return null;
    }

    // Extremely small JSON map parser for merging existing tokens.json (limited scope)
    @SuppressWarnings("unchecked")
    private static Map<String,Object> parseSimpleJsonMap(String s) {
        // very naive: delegate to javax.json absent; keep minimal
        // Expecting flat object with nested objects/arrays of strings/bools
        // For safety, if parsing fails, return empty map
        try {
            // Use java.util.Properties-like approach via org.json not available, so skip
            return new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    private static TokenInfo toTokenInfo(String key, Map<String,Object> m) {
        TokenInfo t = new TokenInfo();
        t.token = key;
        Object p = m.get("protocol"); if (p instanceof String) t.protocol = (String) p;
        Object ex = m.get("examples"); if (ex instanceof List<?> l) for (Object o : l) t.examples.add(String.valueOf(o));
        Object dh = m.get("directionHints"); if (dh instanceof Map<?,?> dm) {
            Object h = dm.get("hostToClient"); if (h instanceof Boolean b && b) t.hostToClient = true;
            Object c = dm.get("clientToHost"); if (c instanceof Boolean b && b) t.clientToHost = true;
        }
        Object sref = m.get("source"); if (sref instanceof String) t.source = (String) sref;
        return t;
    }

    private static void parseManual(Path file, Map<String, ProtocolInfo> protocols, List<AtomInfo> atoms, Map<String, TokenInfo> tokens) throws IOException {
        if (!Files.exists(file)) return;
        try (BufferedReader br = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            String currentProtocolName = null;
            String currentProtocolTag = null;
            Integer currentProtocolId = null;
            StringBuilder currentProtocolSummary = null;
            boolean collectingSummary = false;
            int lineNo = 0;
            while ((line = br.readLine()) != null) {
                lineNo++;
                String trimmed = line.trim();
                Matcher ch = CHAPTER_PROTOCOL.matcher(trimmed);
                if (ch.find()) {
                    // finalize previous protocol summary
                    if (currentProtocolName != null) {
                        ProtocolInfo pi = protocols.computeIfAbsent(currentProtocolTag != null ? currentProtocolTag : currentProtocolName, k -> new ProtocolInfo());
                        pi.name = currentProtocolName;
                        pi.tag = currentProtocolTag;
                        pi.id = currentProtocolId != null ? currentProtocolId : pi.id;
                        if (currentProtocolSummary != null && (pi.summary == null || pi.summary.isEmpty())) {
                            pi.summary = currentProtocolSummary.toString().trim();
                        }
                        if (pi.source == null) pi.source = file.getFileName() + ":" + lineNo;
                    }

                    String title = ch.group(1).trim();
                    currentProtocolName = title;
                    currentProtocolTag = null;
                    currentProtocolId = null;
                    currentProtocolSummary = new StringBuilder();
                    collectingSummary = true;

                    Matcher tagm = PROTOCOL_TAG_PARENS.matcher(trimmed);
                    while (tagm.find()) {
                        String maybe = tagm.group(1);
                        if (maybe != null && maybe.equals(maybe.toUpperCase(Locale.ROOT)) && maybe.length() <= 5) {
                            currentProtocolTag = maybe;
                        }
                    }
                    continue;
                }

                if (collectingSummary) {
                    if (trimmed.isEmpty()) {
                        collectingSummary = false;
                    } else {
                        // accumulate a few lines
                        if (currentProtocolSummary.length() < 2000) {
                            if (currentProtocolSummary.length() > 0) currentProtocolSummary.append(' ');
                            currentProtocolSummary.append(trimmed);
                        }
                    }
                }

                Matcher idm = PROTOCOL_ID.matcher(trimmed);
                if (idm.find() && currentProtocolName != null) {
                    currentProtocolId = parseIntSafe(idm.group(1));
                    ProtocolInfo pi = protocols.computeIfAbsent(currentProtocolTag != null ? currentProtocolTag : currentProtocolName, k -> new ProtocolInfo());
                    pi.name = currentProtocolName;
                    pi.tag = currentProtocolTag;
                    pi.id = currentProtocolId;
                    pi.source = file.getFileName() + ":" + lineNo;
                }

                // atoms
                Matcher am = ATOM_LINE.matcher(trimmed);
                if (am.find()) {
                    String atomName = am.group(1);
                    String signature = null;
                    String synopsis = null;

                    // try immediate signature on the same line
                    Matcher sigSame = ATOM_SIG.matcher(trimmed);
                    if (sigSame.find()) {
                        signature = sigSame.group(2).trim();
                        if (signature.isEmpty()) signature = null;
                    }

                    // peek ahead a few lines to capture signature/synopsis
                    br.mark(10_000);
                    List<String> lookahead = new ArrayList<>();
                    for (int i = 0; i < 6; i++) {
                        br.mark(10_000);
                        String la = br.readLine();
                        if (la == null) break;
                        lookahead.add(la.trim());
                        if (la.trim().startsWith("atom$")) {
                            // rollback to previous mark
                            br.reset();
                            break;
                        }
                    }
                    br.reset();

                    if (signature == null) {
                        for (String la : lookahead) {
                            Matcher sig2 = ATOM_SIG.matcher(la);
                            if (sig2.find() && sig2.group(1).equals(atomName)) {
                                signature = sig2.group(2).trim();
                                break;
                            }
                        }
                    }
                    if (synopsis == null) {
                        for (String la : lookahead) {
                            if (!la.startsWith("atom$") && !la.isEmpty()) {
                                synopsis = la;
                                break;
                            }
                        }
                    }

                    AtomInfo ai = new AtomInfo();
                    ai.name = "atom$" + atomName;
                    ai.protocol = currentProtocolTag != null ? currentProtocolTag : inferProtocolFromAtom(atomName);
                    ai.signature = signature;
                    ai.synopsis = synopsis;
                    ai.source = file.getFileName() + ":" + lineNo;
                    atoms.add(ai);
                }

                // token extraction
                if (trimmed.toLowerCase(Locale.ROOT).contains("token")) {
                    List<String> found = new ArrayList<>();
                    collectToken(found, TOKEN_QUOTED, trimmed);
                    collectToken(found, TOKEN_OF, trimmed);
                    collectToken(found, TOKEN_PAIRED, trimmed);
                    if (!found.isEmpty()) {
                        boolean h2c = HOST_TO_CLIENT.matcher(trimmed).find();
                        boolean c2h = CLIENT_TO_HOST.matcher(trimmed).find();
                        for (String tk : found) {
                            TokenInfo ti = tokens.computeIfAbsent(tk, k -> new TokenInfo());
                            ti.token = tk;
                            if (ti.protocol == null && currentProtocolTag != null) ti.protocol = currentProtocolTag;
                            if (h2c) ti.hostToClient = true;
                            if (c2h) ti.clientToHost = true;
                            if (ti.examples.size() < 3) {
                                ti.examples.add(trimmed);
                            }
                            ti.source = file.getFileName() + ":" + lineNo;
                        }
                    }
                }
            }

            // finalize last protocol summary
            if (currentProtocolName != null) {
                ProtocolInfo pi = protocols.computeIfAbsent(currentProtocolTag != null ? currentProtocolTag : currentProtocolName, k -> new ProtocolInfo());
                pi.name = currentProtocolName;
                pi.tag = currentProtocolTag;
                pi.id = currentProtocolId != null ? currentProtocolId : pi.id;
                if (currentProtocolSummary != null && (pi.summary == null || pi.summary.isEmpty())) {
                    pi.summary = currentProtocolSummary.toString().trim();
                }
                if (pi.source == null) pi.source = file.getFileName() + ":EOF";
            }
        }
    }

    private static void collectToken(Collection<String> out, Pattern p, String line) {
        Matcher m = p.matcher(line);
        while (m.find()) {
            String tk = m.group(1);
            if (tk != null) {
                tk = tk.trim();
                if (tk.length() == 2) {
                    out.add(tk);
                }
            }
        }
    }

    private static String inferProtocolFromAtom(String atomName) {
        for (Map.Entry<String, String> e : ATOM_PREFIX_TO_PROTOCOL.entrySet()) {
            if (atomName.startsWith(e.getKey())) return e.getValue();
        }
        return null;
    }

    private static Integer parseIntSafe(String s) {
        try { return Integer.parseInt(s); } catch (Exception e) { return null; }
    }

    private static void writeProtocols(Path out, Collection<ProtocolInfo> list) throws IOException {
        List<ProtocolInfo> sorted = new ArrayList<>(list);
        sorted.sort(Comparator.comparing((ProtocolInfo p) -> p.tag == null ? p.name : p.tag));
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            w.write("[\n");
            for (int i = 0; i < sorted.size(); i++) {
                ProtocolInfo p = sorted.get(i);
                Map<String, Object> json = new LinkedHashMap<>();
                json.put("name", p.name);
                if (p.tag != null) json.put("tag", p.tag);
                if (p.id != null) json.put("id", p.id);
                if (p.summary != null) json.put("summary", p.summary);
                json.put("source", p.source);
                w.write("  " + toJson(json));
                w.write(i + 1 < sorted.size() ? ",\n" : "\n");
            }
            w.write("]\n");
        }
    }

    private static void writeAtoms(Path out, List<AtomInfo> atoms) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            for (AtomInfo a : atoms) {
                Map<String, Object> json = new LinkedHashMap<>();
                json.put("name", a.name);
                if (a.protocol != null) json.put("protocol", a.protocol);
                if (a.signature != null) json.put("signature", a.signature);
                if (a.synopsis != null) json.put("synopsis", a.synopsis);
                json.put("source", a.source);
                w.write(toJson(json));
                w.write("\n");
            }
        }
    }

    private static void writeTokens(Path out, Map<String, TokenInfo> tokens) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.UTF_8)) {
            Map<String, Object> root = new LinkedHashMap<>();
            for (Map.Entry<String, TokenInfo> e : tokens.entrySet()) {
                TokenInfo t = e.getValue();
                Map<String, Object> j = new LinkedHashMap<>();
                if (t.protocol != null) j.put("protocol", t.protocol);
                if (!t.examples.isEmpty()) j.put("examples", t.examples);
                Map<String, Object> hints = new HashMap<>();
                if (t.hostToClient) hints.put("hostToClient", true);
                if (t.clientToHost) hints.put("clientToHost", true);
                if (!hints.isEmpty()) j.put("directionHints", hints);
                j.put("source", t.source);
                root.put(e.getKey(), j);
            }
            w.write(toJson(root));
            w.write("\n");
        }
    }

    private static String toJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String) return '"' + escape((String) obj) + '"';
        if (obj instanceof Number || obj instanceof Boolean) return obj.toString();
        if (obj instanceof Map<?, ?> map) {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (e.getValue() == null) continue;
                if (!first) sb.append(",");
                first = false;
                sb.append('"').append(escape(Objects.toString(e.getKey()))).append('"').append(":");
                sb.append(toJson(e.getValue()));
            }
            sb.append("}");
            return sb.toString();
        }
        if (obj instanceof Iterable<?> it) {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (Object o : it) {
                if (!first) sb.append(",");
                first = false;
                sb.append(toJson(o));
            }
            sb.append("]");
            return sb.toString();
        }
        return '"' + escape(String.valueOf(obj)) + '"';
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}


