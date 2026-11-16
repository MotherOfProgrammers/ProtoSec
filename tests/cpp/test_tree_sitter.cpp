#include "../../core/include/scanner.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void writeFile(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output || !(output << contents)) {
        throw std::runtime_error("Could not write scanner test input");
    }
}

std::size_t countRule(const ScanReport& report, const std::string& rule_id) {
    std::size_t count = 0;
    for (const auto& finding : report.findings) {
        if (finding.rule_id == rule_id) {
            ++count;
        }
    }
    return count;
}

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        throw std::runtime_error("Expected a writable test workspace path");
    }

    const fs::path workspace = argv[1];
    fs::remove_all(workspace);
    writeFile(
        workspace / "source.ts",
        "// sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "const apiKey = \"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n"
        "const value = eval(input);\n"
    );
    writeFile(
        workspace / "comment.js",
        "// sk-cccccccccccccccccccccccccccccccccccccccc\n"
    );
    writeFile(
        workspace / "comment.tsx",
        "const view = <div />; // sk-ffffffffffffffffffffffffffffffffffffffff\n"
    );
    writeFile(
        workspace / "comment.py",
        "# sk-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"
    );
    writeFile(
        workspace / "schema.sql",
        "-- CREATE TABLE public.ignored (id integer);\n"
        "CREATE TABLE public.accounts (id integer);\n"
    );
    writeFile(
        workspace / "__tests__" / "ignored.ts",
        "const apiKey = \"sk-cccccccccccccccccccccccccccccccccccccccc\";\n"
    );
    const auto outside_file = workspace.parent_path() / "outside-secret.py";
    writeFile(
        outside_file,
        "token = \"sk-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\";\n"
    );
    std::error_code symlink_error;
    fs::create_symlink(outside_file, workspace / "linked.py", symlink_error);

    const Scanner scanner(workspace, workspace);
    const auto report = scanner.run();
    fs::remove(outside_file);
    require(report.files_scanned == 5, "Common test directories should be excluded");
    require(countRule(report, "SEC-001") == 1, "A code string secret should be detected once");
    require(countRule(report, "DB-004") == 1, "Only the parsed SQL table should be checked");
    for (const auto& finding : report.findings) {
        if (finding.rule_id == "DB-004") {
            require(finding.line_number == 2, "SQL finding should retain its source line");
        }
    }
    const auto selected_report = scanner.runFiles({fs::path("source.ts")});
    require(selected_report.files_scanned == 1, "Selected-file scans should omit unchanged files");
    require(countRule(selected_report, "SEC-001") == 1, "Selected-file scans should retain findings");
    const auto single_rule_report = scanner.runFiles(
        {fs::path("source.ts")},
        std::vector<std::string>{"SEC-001"}
    );
    require(countRule(single_rule_report, "SEC-001") == 1, "Selected-rule scans should run the requested rule");
    require(countRule(single_rule_report, "INJ-002") == 0, "Selected-rule scans should omit other rules");
    writeFile(
        workspace / "tainted.ts",
        "async function handler(req: any, db: any) {\n"
        "  const id = req.body.id;\n"
        "  const sql = `SELECT * FROM accounts WHERE id=${id}`;\n"
        "  db.query(sql);\n"
        "}\n"
        "function unrelated(db: any) {\n"
        "  db.query(sql);\n"
        "}\n"
    );
    writeFile(
        workspace / "safe.py",
        "def handler(request, cursor):\n"
        "    user_id = request.args.get('id')\n"
        "    cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))\n"
    );
    writeFile(
        workspace / "tainted.py",
        "def handler(request, cursor):\n"
        "    user_id = request.args.get('id')\n"
        "    sql = 'SELECT * FROM accounts WHERE id=' + user_id\n"
        "    cursor.execute(sql)\n"
        "def unrelated(cursor):\n"
        "    cursor.execute(sql)\n"
        "def dynamic(request):\n"
        "    eval(request.args.get('code'))\n"
    );
    writeFile(
        workspace / "interprocedural.py",
        "def execute_query(cursor, query):\n"
        "    cursor.execute(query)\n"
        "def build_sql(value):\n"
        "    prefix = 'SELECT * FROM accounts WHERE id='\n"
        "    if value:\n"
        "        query = prefix + value\n"
        "    else:\n"
        "        query = prefix + '1'\n"
        "    return query\n"
        "def handler(request, cursor):\n"
        "    raw = request.args.get('id')\n"
        "    sql = build_sql(raw)\n"
        "    execute_query(cursor, sql)\n"
        "    safe_id = int(request.args.get('number'))\n"
        "    cursor.execute(f'SELECT * FROM accounts WHERE id={safe_id}')\n"
    );
    writeFile(
        workspace / "interprocedural.ts",
        "const execute = (query: any, db: any) => db.query(query);\n"
        "function buildSql(id: any) {\n"
        "  const query = `SELECT * FROM accounts WHERE id=${id}`;\n"
        "  return query;\n"
        "}\n"
        "function handler(req: any, db: any) {\n"
        "  const id = req.body.id;\n"
        "  const query = buildSql(id);\n"
        "  execute(query, db);\n"
        "  const safeId = Number(req.body.numeric);\n"
        "  db.query(`SELECT * FROM accounts WHERE id=${safeId}`);\n"
        "}\n"
    );
    writeFile(
        workspace / "interprocedural.js",
        "const execute = (query, db) => db.query(query);\n"
        "function buildSql(id) {\n"
        "  return `SELECT * FROM accounts WHERE id=${id}`;\n"
        "}\n"
        "function handler(req, db) {\n"
        "  execute(buildSql(req.query.id), db);\n"
        "}\n"
    );
    const auto taint_report = scanner.runFiles(
        {
            fs::path("tainted.ts"),
            fs::path("safe.py"),
            fs::path("tainted.py"),
            fs::path("interprocedural.py"),
            fs::path("interprocedural.ts"),
            fs::path("interprocedural.js"),
        },
        std::vector<std::string>{"DATA-001"}
    );
    require(
        countRule(taint_report, "DATA-001") == 6,
        "Data-flow analysis should detect assignment, branch, argument, and return propagation"
    );
    bool python_sql_line = false;
    bool python_eval_line = false;
    bool typescript_sql_line = false;
    bool python_flow_evidence = false;
    bool typescript_flow_evidence = false;
    bool javascript_flow_evidence = false;
    for (const auto& finding : taint_report.findings) {
        if (finding.rule_id != "DATA-001") {
            continue;
        }
        require(
            finding.cwe_id ==
                (finding.title.find("dynamic code") != std::string::npos
                    ? "CWE-94"
                    : "CWE-89"),
            "Data-flow findings should include the matching CWE identifier"
        );
        if (finding.file_path == "tainted.py") {
            python_sql_line = python_sql_line || finding.line_number == 4;
            python_eval_line = python_eval_line || finding.line_number == 8;
        } else if (finding.file_path == "tainted.ts") {
            typescript_sql_line = finding.line_number == 4;
        } else if (finding.file_path == "interprocedural.py") {
            python_flow_evidence =
                finding.line_number == 2 &&
                std::find(finding.data_flow_lines.begin(), finding.data_flow_lines.end(), 11) !=
                    finding.data_flow_lines.end();
        } else if (finding.file_path == "interprocedural.ts") {
            typescript_flow_evidence =
                finding.line_number == 1 &&
                std::find(finding.data_flow_lines.begin(), finding.data_flow_lines.end(), 7) !=
                    finding.data_flow_lines.end();
        } else if (finding.file_path == "interprocedural.js") {
            javascript_flow_evidence =
                finding.line_number == 1 &&
                std::find(finding.data_flow_lines.begin(), finding.data_flow_lines.end(), 6) !=
                    finding.data_flow_lines.end();
        }
    }
    require(
        python_sql_line && python_eval_line && typescript_sql_line,
        "Data-flow findings should identify each sink line"
    );
    require(python_flow_evidence, "Python findings should include source-to-sink line evidence");
    require(
        typescript_flow_evidence,
        "TypeScript findings should include source-to-sink line evidence"
    );
    require(
        javascript_flow_evidence,
        "JavaScript findings should include source-to-sink line evidence"
    );
    bool rejected_traversal = false;
    try {
        static_cast<void>(scanner.runFiles({fs::path("../outside-secret.py")}));
    } catch (const std::invalid_argument&) {
        rejected_traversal = true;
    }
    require(rejected_traversal, "Selected-file scans must reject paths outside the project");
    return 0;
}
