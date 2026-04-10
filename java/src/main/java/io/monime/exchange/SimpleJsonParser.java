package io.monime.exchange;

import java.util.*;

/**
 * Minimal recursive-descent JSON parser.
 * Supports objects, arrays, strings, numbers, booleans, and null.
 * No external dependencies required.
 */
class SimpleJsonParser {
    private final String input;
    private int pos;

    SimpleJsonParser(String input) {
        this.input = input;
        this.pos = 0;
    }

    Object parse() {
        skipWhitespace();
        Object value = readValue();
        skipWhitespace();
        return value;
    }

    private Object readValue() {
        skipWhitespace();
        if (pos >= input.length()) {
            throw new RuntimeException("Unexpected end of JSON");
        }

        char c = input.charAt(pos);
        switch (c) {
            case '{': return readObject();
            case '[': return readArray();
            case '"': return readString();
            case 't': case 'f': return readBoolean();
            case 'n': return readNull();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) {
                    return readNumber();
                }
                throw new RuntimeException("Unexpected character '" + c + "' at position " + pos);
        }
    }

    private Map<String, Object> readObject() {
        expect('{');
        Map<String, Object> map = new LinkedHashMap<>();
        skipWhitespace();

        if (pos < input.length() && input.charAt(pos) == '}') {
            pos++;
            return map;
        }

        while (true) {
            skipWhitespace();
            String key = readString();
            skipWhitespace();
            expect(':');
            Object value = readValue();
            map.put(key, value);
            skipWhitespace();

            if (pos < input.length() && input.charAt(pos) == ',') {
                pos++;
            } else {
                break;
            }
        }

        expect('}');
        return map;
    }

    private List<Object> readArray() {
        expect('[');
        List<Object> list = new ArrayList<>();
        skipWhitespace();

        if (pos < input.length() && input.charAt(pos) == ']') {
            pos++;
            return list;
        }

        while (true) {
            list.add(readValue());
            skipWhitespace();

            if (pos < input.length() && input.charAt(pos) == ',') {
                pos++;
            } else {
                break;
            }
        }

        expect(']');
        return list;
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();

        while (pos < input.length()) {
            char c = input.charAt(pos);
            if (c == '"') {
                pos++;
                return sb.toString();
            }
            if (c == '\\') {
                pos++;
                if (pos >= input.length()) break;
                char esc = input.charAt(pos);
                switch (esc) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'u':
                        if (pos + 4 < input.length()) {
                            String hex = input.substring(pos + 1, pos + 5);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                        }
                        break;
                    default: sb.append(esc);
                }
            } else {
                sb.append(c);
            }
            pos++;
        }

        throw new RuntimeException("Unterminated string");
    }

    private Number readNumber() {
        int start = pos;

        if (pos < input.length() && input.charAt(pos) == '-') pos++;
        while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') pos++;

        boolean isFloat = false;
        if (pos < input.length() && input.charAt(pos) == '.') {
            isFloat = true;
            pos++;
            while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') pos++;
        }
        if (pos < input.length() && (input.charAt(pos) == 'e' || input.charAt(pos) == 'E')) {
            isFloat = true;
            pos++;
            if (pos < input.length() && (input.charAt(pos) == '+' || input.charAt(pos) == '-')) pos++;
            while (pos < input.length() && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') pos++;
        }

        String numStr = input.substring(start, pos);
        if (isFloat) {
            return Double.parseDouble(numStr);
        }

        long val = Long.parseLong(numStr);
        if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) {
            return (int) val;
        }
        return val;
    }

    private Boolean readBoolean() {
        if (input.startsWith("true", pos)) {
            pos += 4;
            return true;
        }
        if (input.startsWith("false", pos)) {
            pos += 5;
            return false;
        }
        throw new RuntimeException("Expected boolean at position " + pos);
    }

    private Object readNull() {
        if (input.startsWith("null", pos)) {
            pos += 4;
            return null;
        }
        throw new RuntimeException("Expected null at position " + pos);
    }

    private void expect(char c) {
        skipWhitespace();
        if (pos >= input.length() || input.charAt(pos) != c) {
            throw new RuntimeException("Expected '" + c + "' at position " + pos);
        }
        pos++;
    }

    private void skipWhitespace() {
        while (pos < input.length()) {
            char c = input.charAt(pos);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
            pos++;
        }
    }
}
