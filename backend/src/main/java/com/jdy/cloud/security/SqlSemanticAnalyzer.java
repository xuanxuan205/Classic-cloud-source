package com.jdy.cloud.security;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * IronWall v1.31.0: SQL 词法/语义检测层。
 * 规则层（正则）全部未命中后才运行；输入必须含引号/反引号/注释/分号等注入形态才激活。
 * 通过轻量词法器做结构判定，一次性覆盖双写/转义/引号族/子句族等正则难覆盖变体。
 * 仅返回「SQL 语句结构成立」的判定，自然语言负样本不命中。
 */
public final class SqlSemanticAnalyzer {

    private static final Pattern DOUBLE_WRITE = Pattern.compile(
            "(?i)\\b(oorr|anandd|uniunionon|selselectect|slesleepp)\\b");

    private static final Set<String> STATEMENT_KEYWORDS = Set.of(
            "select", "insert", "update", "delete", "drop", "create", "alter", "truncate",
            "exec", "declare", "grant", "show", "union", "merge", "replace");

    private static final Set<String> COMPARATORS = Set.of(
            "=", "<", ">", "<=", ">=", "<>", "!=", "like", "in", "is", "between", "regexp", "rlike");

    /** 引号逃逸后允许紧跟的 SQL 关键字（用于布尔注入前置判定）。 */
    private static final Set<String> BOOLEAN_KEYWORDS = Set.of("or", "and");

    /** FROM 后自然语言停用词（"select apples from the store" 等短语不构成表名）。 */
    private static final Set<String> STOPWORDS = Set.of(
            "the", "a", "an", "my", "your", "our", "their", "his", "her", "its",
            "this", "that", "these", "those", "some", "any", "all", "many", "few",
            "each", "every", "both", "no", "not");

    /** FROM 短语合法的 SQL 终止边界（自然语句不会有 where/order/join 等后续）。 */
    private static final Set<String> FROM_BOUNDARIES = Set.of(
            "where", "order", "group", "having", "limit", "offset", "union",
            "join", "inner", "left", "right", "cross", "natural", "on", "into", "for");

    private enum Kind { WORD, NUMBER, QUOTE, OP }

    private record Token(Kind kind, String value) {
    }

    /** 结构判定：命中返回原因，未命中返回 null。 */
    public String findSql(String input) {
        if (input == null || input.isEmpty()) return null;
        boolean injectionShaped = input.indexOf('\'') >= 0 || input.indexOf('"') >= 0 || input.indexOf('`') >= 0
                || input.indexOf(';') >= 0 || input.contains("--") || input.indexOf('#') >= 0 || input.contains("/*");
        if (!injectionShaped) return null;
        String cleaned = dedupDoubleWrite(input);
        List<Token> tokens = lex(cleaned);
        if (tokens.size() < 2) return null;
        if (unionSelect(tokens)) return "SQL语义: UNION注入结构";
        if (booleanInjection(tokens)) return "SQL语义: 布尔注入结构";
        if (stackedQuery(tokens)) return "SQL语义: 堆叠查询结构";
        if (selectStatement(tokens)) return "SQL语义: SELECT语句结构";
        if (dmlStatement(tokens)) return "SQL语义: 写操作语句结构";
        return null;
    }

    private String dedupDoubleWrite(String input) {
        String out = input;
        for (int i = 0; i < 4; i++) {
            String next = DOUBLE_WRITE.matcher(out).replaceAll(mr -> {
                switch (mr.group(1).toLowerCase()) {
                    case "oorr": return "or";
                    case "anandd": return "and";
                    case "uniunionon": return "union";
                    case "selselectect": return "select";
                    case "slesleepp": return "sleep";
                    default: return mr.group();
                }
            });
            if (next.equals(out)) break;
            out = next;
        }
        return out;
    }

    /**
     * 词法切分：注释剥离（-- / # / /​* *​/），引号一律作为独立 QUOTE 标记
     * （保留「引号逃逸」视图，字符串内容继续按 SQL 词法扫描），
     * 单词小写归一，运算符/标点独立成 token。
     */
    private List<Token> lex(String input) {
        String text;
        try {
            text = Normalizer.normalize(input, Normalizer.Form.NFKC);
        } catch (Exception e) {
            text = input;
        }
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int n = text.length();
        while (i < n) {
            char c = text.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (c == '-' && i + 1 < n && text.charAt(i + 1) == '-') {
                while (i < n && text.charAt(i) != '\n' && text.charAt(i) != '\r') i++;
                continue;
            }
            if (c == '#') {
                while (i < n && text.charAt(i) != '\n' && text.charAt(i) != '\r') i++;
                continue;
            }
            if (c == '/' && i + 1 < n && text.charAt(i + 1) == '*') {
                int end = text.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`') {
                tokens.add(new Token(Kind.QUOTE, String.valueOf(c)));
                i++;
                continue;
            }
            if (Character.isDigit(c)) {
                int start = i;
                while (i < n && (Character.isDigit(text.charAt(i)) || text.charAt(i) == '.')) i++;
                tokens.add(new Token(Kind.NUMBER, text.substring(start, i)));
                continue;
            }
            if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < n && (Character.isLetterOrDigit(text.charAt(i)) || text.charAt(i) == '_' || text.charAt(i) == '.')) i++;
                tokens.add(new Token(Kind.WORD, text.substring(start, i).toLowerCase()));
                continue;
            }
            if (i + 1 < n) {
                String two = text.substring(i, i + 2);
                if ("<=".equals(two) || ">=".equals(two) || "<>".equals(two) || "!=".equals(two)
                        || "||".equals(two) || "&&".equals(two)) {
                    tokens.add(new Token(Kind.OP, two));
                    i += 2;
                    continue;
                }
            }
            if ("=<>+-*/%~(),.;".indexOf(c) >= 0) {
                tokens.add(new Token(Kind.OP, String.valueOf(c)));
                i++;
                continue;
            }
            i++;
        }
        return tokens;
    }

    private boolean unionSelect(List<Token> tokens) {
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (!isWord(tokens.get(i), "union")) continue;
            int j = i + 1;
            if (j < tokens.size() && isWord(tokens.get(j), "all", "distinct")) j++;
            if (j < tokens.size() && isWord(tokens.get(j), "select")) return true;
        }
        return false;
    }

    /** 布尔注入：引号逃逸点后 OR/AND + 字面量 + 比较符 + 字面量（容忍引号/括号包裹）。 */
    private boolean booleanInjection(List<Token> tokens) {
        for (int i = 1; i < tokens.size(); i++) {
            Token t = tokens.get(i);
            if (t.kind() != Kind.WORD || !BOOLEAN_KEYWORDS.contains(t.value())) continue;
            Token prev = tokens.get(i - 1);
            boolean precededByEscape = prev.kind() == Kind.QUOTE || isOp(prev, "(", ")", ";", "||", "&&");
            if (!precededByEscape) continue;
            int j = skipWraps(tokens, i + 1);
            if (j >= tokens.size() || !isLiteral(tokens.get(j))) continue;
            j = skipWraps(tokens, j + 1);
            if (j >= tokens.size() || !isComparator(tokens.get(j))) continue;
            j = skipWraps(tokens, j + 1);
            if (j < tokens.size() && isLiteral(tokens.get(j))) return true;
        }
        return false;
    }

    /** 堆叠查询：; 后紧跟语句关键字。 */
    private boolean stackedQuery(List<Token> tokens) {
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (!isOp(tokens.get(i), ";")) continue;
            Token next = tokens.get(i + 1);
            if (next.kind() == Kind.WORD && STATEMENT_KEYWORDS.contains(next.value())) return true;
        }
        return false;
    }

    /**
     * SELECT ... FROM 语句结构。
     * select 前置必须是 起始/引号/(/,/;/=/union（排除 "don't select" 之类自然语句）；
     * 无论前置为何，select 后随列必须为 * /数字/引号/逗号列/函数调用形态；
     * 逃逸路径额外接受「词列 FROM 表名」形态，但表名必须非停用词且短语
     * 终止于 SQL 边界（排除 "select apples from the store" 之类自然语句）。
     */
    private boolean selectStatement(List<Token> tokens) {
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (!isWord(tokens.get(i), "select")) continue;
            int j = i + 1;
            if (j < tokens.size() && isWord(tokens.get(j), "all", "distinct", "top", "high_priority", "sql_no_cache", "sql_calc_found_rows")) j++;
            if (j >= tokens.size()) continue;
            Token first = tokens.get(j);
            boolean columnLooksSql = isOp(first, "*", "(")
                    || first.kind() == Kind.NUMBER
                    || first.kind() == Kind.QUOTE
                    || (first.kind() == Kind.WORD && j + 1 < tokens.size()
                        && isOp(tokens.get(j + 1), ",", "("));
            boolean wordFromSql = first.kind() == Kind.WORD
                    && j + 2 < tokens.size()
                    && isWord(tokens.get(j + 1), "from")
                    && tokens.get(j + 2).kind() == Kind.WORD
                    && !STOPWORDS.contains(tokens.get(j + 2).value())
                    && fromPhraseTerminates(tokens, j + 3);
            boolean fromInRange = false;
            for (int k = j; k < tokens.size() && k <= j + 8; k++) {
                if (isWord(tokens.get(k), "from")) {
                    fromInRange = true;
                    break;
                }
            }
            if (!fromInRange) continue;
            if (i == 0) {
                if (columnLooksSql) return true;
                continue;
            }
            Token prev = tokens.get(i - 1);
            boolean escapedOk = prev.kind() == Kind.QUOTE
                    || isOp(prev, "(", ",", ";", "=", ")", "||", "&&")
                    || isWord(prev, "union");
            if (escapedOk && (columnLooksSql || wordFromSql)) return true;
        }
        return false;
    }

    /** FROM 表名之后必须是结束/括号/逗号/分号或 SQL 子句关键字，防止自然语句误报。 */
    private boolean fromPhraseTerminates(List<Token> tokens, int index) {
        if (index >= tokens.size()) return true;
        Token t = tokens.get(index);
        if (t.kind() == Kind.OP && (")".equals(t.value()) || ",".equals(t.value()) || ";".equals(t.value()))) return true;
        return t.kind() == Kind.WORD && FROM_BOUNDARIES.contains(t.value());
    }

    /** INSERT INTO / DROP|ALTER|TRUNCATE|CREATE TABLE 写操作结构（前置为 起始/引号/;/;/(且含 SQL 后续信号）。 */
    private boolean dmlStatement(List<Token> tokens) {
        for (int i = 0; i < tokens.size() - 1; i++) {
            Token t = tokens.get(i);
            if (t.kind() != Kind.WORD) continue;
            boolean insertInto = "insert".equals(t.value()) && i + 1 < tokens.size() && isWord(tokens.get(i + 1), "into");
            boolean ddl = ("drop".equals(t.value()) || "alter".equals(t.value())
                    || "truncate".equals(t.value()) || "create".equals(t.value()))
                    && i + 1 < tokens.size() && isWord(tokens.get(i + 1), "table", "database", "index");
            if (!insertInto && !ddl) continue;
            boolean precededOk = i == 0
                    || tokens.get(i - 1).kind() == Kind.QUOTE
                    || isOp(tokens.get(i - 1), ";", "(", ")", "=");
            if (!precededOk) continue;
            for (int k = i + 1; k < tokens.size() && k <= i + 8; k++) {
                Token f = tokens.get(k);
                if (isWord(f, "values", "select", "where", "set")) return true;
                if (f.kind() == Kind.OP && ("(".equals(f.value()) || ",".equals(f.value()))) return true;
            }
        }
        return false;
    }

    private int skipWraps(List<Token> tokens, int index) {
        int j = index;
        int guard = 0;
        while (j < tokens.size() && guard < 3
                && (tokens.get(j).kind() == Kind.QUOTE || isOp(tokens.get(j), "(", ")"))) {
            j++;
            guard++;
        }
        return j;
    }

    private boolean isLiteral(Token t) {
        return t.kind() == Kind.NUMBER || t.kind() == Kind.WORD || t.kind() == Kind.QUOTE;
    }

    private boolean isComparator(Token t) {
        if (t.kind() == Kind.OP && COMPARATORS.contains(t.value())) return true;
        return t.kind() == Kind.WORD && COMPARATORS.contains(t.value());
    }

    private boolean isWord(Token t, String... values) {
        if (t.kind() != Kind.WORD) return false;
        for (String v : values) {
            if (v.equals(t.value())) return true;
        }
        return false;
    }

    private boolean isOp(Token t, String... values) {
        if (t.kind() != Kind.OP) return false;
        for (String v : values) {
            if (v.equals(t.value())) return true;
        }
        return false;
    }
}
