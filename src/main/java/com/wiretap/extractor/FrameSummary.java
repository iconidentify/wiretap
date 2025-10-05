package com.wiretap.extractor;

public final class FrameSummary {
    public String dir;
    public String ts;
    public String token;
    public String streamId;
    public String type;
    public String tx;
    public String rx;
    public int len;
    public Boolean crcOk;
    public String atoms;
    public String preview;
    public String fullHex;
    public String ref;

    // Enrichment fields (optional)
    public String protocolTag;
    public String tokenName;
    public String tokenDesc;
    public String docRef;

    // Optional payload sampling
    public String payloadHex;   // truncated hex of payload bytes
    public String payloadText;  // printable ASCII sample of payload

    // Analysis flags
    public Boolean hasError;    // true if any anomaly detected
    public String errorCodes;   // comma-separated error codes (e.g., "CRC")

    // FDO decompilation
    public String fdoSource;    // Decompiled FDO source code or formatted data frame info

    public String toJson(boolean pretty) {
        String q = "\"";
        String comma = pretty ? ", " : ",";
        int est = 64;
        if (dir != null) est += 8 + dir.length();
        if (ts != null) est += 8 + ts.length();
        if (token != null) est += 10 + token.length();
        if (streamId != null) est += 14 + streamId.length();
        if (type != null) est += 9 + type.length();
        if (tx != null) est += 7 + tx.length();
        if (rx != null) est += 7 + rx.length();
        if (atoms != null) est += 11 + atoms.length();
        if (preview != null) est += 13 + preview.length();
        if (ref != null) est += 8 + ref.length();
        if (fullHex != null) est += 12 + fullHex.length();
        if (payloadHex != null) est += 14 + payloadHex.length();
        if (payloadText != null) est += 16 + payloadText.length();
        if (hasError != null) est += 12;
        if (errorCodes != null) est += 14 + errorCodes.length();
        if (protocolTag != null) est += 16 + protocolTag.length();
        if (tokenName != null) est += 14 + tokenName.length();
        if (tokenDesc != null) est += 14 + tokenDesc.length();
        if (docRef != null) est += 12 + docRef.length();
        if (fdoSource != null) est += 14 + fdoSource.length();
        StringBuilder sb = new StringBuilder(Math.min(est, 4096));
        sb.append("{");
        boolean first = true;

        if (dir != null) { if (!first) sb.append(comma); add(sb,"dir",dir,""); first = false; }
        if (ts != null) { if (!first) sb.append(comma); add(sb,"ts",ts,""); first = false; }
        if (token != null) { if (!first) sb.append(comma); add(sb,"token",token,""); first = false; }
        if (streamId != null) { if (!first) sb.append(comma); add(sb,"streamId",streamId,""); first = false; }
        if (type != null) { if (!first) sb.append(comma); add(sb,"type",type,""); first = false; }
        if (tx != null) { if (!first) sb.append(comma); add(sb,"tx",tx,""); first = false; }
        if (rx != null) { if (!first) sb.append(comma); add(sb,"rx",rx,""); first = false; }

        if (!first) sb.append(comma);
        sb.append(q).append("len").append(q).append(":").append(len);

        if (crcOk != null) { sb.append(comma); sb.append(q).append("crcOk").append(q).append(":").append(crcOk); }
        if (atoms != null) { sb.append(comma); add(sb,"atoms",atoms,""); }
        if (preview != null) { sb.append(comma); add(sb,"preview",preview,""); }
        if (ref != null) { sb.append(comma); add(sb,"ref",ref,""); }
        if (fullHex != null) { sb.append(comma); add(sb,"fullHex",fullHex,""); }
        if (payloadHex != null) { sb.append(comma); add(sb,"payloadHex",payloadHex,""); }
        if (payloadText != null) { sb.append(comma); add(sb,"payloadText",payloadText,""); }
        if (protocolTag != null) { sb.append(comma); add(sb,"protocolTag",protocolTag,""); }
        if (tokenName != null) { sb.append(comma); add(sb,"tokenName",tokenName,""); }
        if (tokenDesc != null) { sb.append(comma); add(sb,"tokenDesc",tokenDesc,""); }
        if (docRef != null) { sb.append(comma); add(sb,"docRef",docRef,""); }
        if (hasError != null) { sb.append(comma); sb.append(q).append("hasError").append(q).append(":").append(hasError); }
        if (errorCodes != null) { sb.append(comma); add(sb,"errorCodes",errorCodes,""); }
        if (fdoSource != null) { sb.append(comma); add(sb,"fdoSource",fdoSource,""); }

        sb.append("}");
        return sb.toString();
    }

    private static void add(StringBuilder sb, String k, String v, String comma) {
        if (v == null) return;
        sb.append("\"").append(k).append("\":");
        sb.append("\"").append(escape(v)).append("\"").append(comma);
    }
    private static String escape(String s) {
        return s.replace("\\","\\\\").replace("\"","\\\"")
                .replace("\n","\\n").replace("\r","\\r");
    }
}


