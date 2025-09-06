package com.wiretap.core;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Simple JSON utility class using only JDK classes for maximum GraalVM compatibility.
 * Handles basic JSON operations needed by WireTap.
 */
public final class JsonUtil {

    /**
     * Convert an object to JSON string.
     * For now, handles basic types and simple objects.
     */
    public static String toJson(Object obj) {
        if (obj == null) {
            return "null";
        }

        if (obj instanceof String) {
            return "\"" + escapeJsonString((String) obj) + "\"";
        }

        if (obj instanceof Number || obj instanceof Boolean) {
            return obj.toString();
        }

        if (obj instanceof List) {
            return toJsonArray((List<?>) obj);
        }

        if (obj instanceof Map) {
            return toJsonObject((Map<?, ?>) obj);
        }

        // For custom objects, use reflection to get fields
        return toJsonFromFields(obj);
    }

    /**
     * Convert a List to JSON array string.
     */
    private static String toJsonArray(List<?> list) {
        return "[" + list.stream()
                .map(JsonUtil::toJson)
                .collect(Collectors.joining(",")) + "]";
    }

    /**
     * Convert a Map to JSON object string.
     */
    private static String toJsonObject(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) {
                sb.append(",");
            }
            sb.append("\"").append(escapeJsonString(entry.getKey().toString())).append("\":");
            sb.append(toJson(entry.getValue()));
            first = false;
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert an object to JSON using reflection on public fields.
     */
    private static String toJsonFromFields(Object obj) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        Class<?> clazz = obj.getClass();
        java.lang.reflect.Field[] fields = clazz.getFields(); // Only public fields

        boolean first = true;
        for (java.lang.reflect.Field field : fields) {
            try {
                Object value = field.get(obj);
                if (value != null) { // Skip null values for simplicity
                    if (!first) {
                        sb.append(",");
                    }
                    sb.append("\"").append(field.getName()).append("\":");
                    sb.append(toJson(value));
                    first = false;
                }
            } catch (IllegalAccessException e) {
                // Skip inaccessible fields
            }
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Parse a simple JSON object string to a Map.
     * Only handles basic JSON structures.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> fromJson(String json) {
        if (json == null || json.trim().isEmpty()) {
            return new HashMap<>();
        }

        json = json.trim();
        if (json.startsWith("{") && json.endsWith("}")) {
            return parseJsonObject(json.substring(1, json.length() - 1));
        }

        throw new IllegalArgumentException("Invalid JSON format");
    }

    /**
     * Parse JSON object content (without braces) into a Map.
     */
    private static Map<String, Object> parseJsonObject(String content) {
        Map<String, Object> result = new HashMap<>();

        int i = 0;
        while (i < content.length()) {
            // Skip whitespace
            while (i < content.length() && Character.isWhitespace(content.charAt(i))) {
                i++;
            }
            if (i >= content.length()) break;

            // Parse key
            if (content.charAt(i) != '"') {
                throw new IllegalArgumentException("Expected string key at position " + i);
            }
            i++; // Skip opening quote

            StringBuilder key = new StringBuilder();
            while (i < content.length() && content.charAt(i) != '"') {
                if (content.charAt(i) == '\\') {
                    i++; // Skip escape character
                }
                key.append(content.charAt(i));
                i++;
            }
            i++; // Skip closing quote

            // Skip whitespace and colon
            while (i < content.length() && (Character.isWhitespace(content.charAt(i)) || content.charAt(i) == ':')) {
                i++;
            }

            // Parse value
            Object value = parseJsonValue(content, i);
            i = value instanceof Integer ? ((Integer) value).intValue() : i;

            result.put(key.toString(), value);

            // Skip whitespace and comma
            while (i < content.length() && (Character.isWhitespace(content.charAt(i)) || content.charAt(i) == ',')) {
                i++;
            }
        }

        return result;
    }

    /**
     * Parse a JSON value and return the value and updated position.
     */
    private static Object parseJsonValue(String content, int startPos) {
        int i = startPos;

        // Skip whitespace
        while (i < content.length() && Character.isWhitespace(content.charAt(i))) {
            i++;
        }

        if (i >= content.length()) {
            throw new IllegalArgumentException("Unexpected end of JSON");
        }

        char c = content.charAt(i);

        if (c == '"') {
            // String value
            i++; // Skip opening quote
            StringBuilder value = new StringBuilder();
            while (i < content.length() && content.charAt(i) != '"') {
                if (content.charAt(i) == '\\') {
                    i++; // Skip escape character
                }
                value.append(content.charAt(i));
                i++;
            }
            i++; // Skip closing quote
            return value.toString();
        } else if (c == '{') {
            // Object value - find matching closing brace
            int braceCount = 1;
            i++;
            int start = i;
            while (i < content.length() && braceCount > 0) {
                if (content.charAt(i) == '{') {
                    braceCount++;
                } else if (content.charAt(i) == '}') {
                    braceCount--;
                }
                i++;
            }
            String objectContent = content.substring(start, i - 1);
            return parseJsonObject(objectContent);
        } else if (c == '[') {
            // Array value - simplified handling
            int bracketCount = 1;
            i++;
            List<Object> array = new ArrayList<>();
            while (i < content.length() && bracketCount > 0) {
                if (content.charAt(i) == '[') {
                    bracketCount++;
                } else if (content.charAt(i) == ']') {
                    bracketCount--;
                    if (bracketCount == 0) break;
                } else if (content.charAt(i) == ',' && bracketCount == 1) {
                    // Skip commas at top level
                } else if (!Character.isWhitespace(content.charAt(i))) {
                    // Parse array element (simplified)
                    if (content.charAt(i) == '"') {
                        // String element
                        int start = i;
                        i++;
                        while (i < content.length() && content.charAt(i) != '"') {
                            if (content.charAt(i) == '\\') i++;
                            i++;
                        }
                        i++; // Skip closing quote
                        array.add(content.substring(start + 1, i - 1));
                    }
                }
                i++;
            }
            return array;
        } else if (Character.isDigit(c) || c == '-') {
            // Number value
            StringBuilder numStr = new StringBuilder();
            while (i < content.length() && (Character.isDigit(content.charAt(i)) ||
                   content.charAt(i) == '.' || content.charAt(i) == '-')) {
                numStr.append(content.charAt(i));
                i++;
            }
            try {
                return Integer.parseInt(numStr.toString());
            } catch (NumberFormatException e) {
                try {
                    return Double.parseDouble(numStr.toString());
                } catch (NumberFormatException e2) {
                    return 0;
                }
            }
        } else if (content.startsWith("true", i)) {
            i += 4;
            return true;
        } else if (content.startsWith("false", i)) {
            i += 5;
            return false;
        } else if (content.startsWith("null", i)) {
            i += 4;
            return null;
        }

        // Return position for caller to handle
        return i;
    }

    /**
     * Escape special characters in JSON strings.
     */
    private static String escapeJsonString(String str) {
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Pretty print JSON (simple implementation).
     */
    public static String toJsonPretty(Object obj) {
        return toJson(obj); // For now, just return regular JSON
    }
}
