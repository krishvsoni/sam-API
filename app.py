from flask import Flask, request, jsonify
from luaparser import ast, astnodes
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

INT_MAX = 2147483647
INT_MIN = -2147483648

vulnerabilities = []


def add_vulnerability(name, description, pattern, severity, line):
    vulnerabilities.append(
        {
            "name": name,
            "description": description,
            "pattern": pattern,
            "severity": severity,
            "line": line,
        }
    )


def is_potential_overflow(number):
    return number >= INT_MAX or number <= INT_MIN


def is_potential_underflow(number):
    return number <= INT_MIN or number >= INT_MAX


def get_line_number(node):
    if hasattr(node, "line") and node.line is not None:
        return node.line
    if hasattr(node, "_parent"):
        return get_line_number(node._parent)
    return None


def analyze_overflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_overflow(
            left_operand.n
        ):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with left operand.",
                "overflow",
                "high",
                get_line_number(left_operand),
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_overflow(
            right_operand.n
        ):
            add_vulnerability(
                "Integer Overflow",
                "Potential integer overflow detected with right operand.",
                "overflow",
                "high",
                get_line_number(right_operand),
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_overflow(value.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with local variable assignment.",
                    "overflow",
                    "high",
                    get_line_number(value),
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_overflow(arg.n):
                add_vulnerability(
                    "Integer Overflow",
                    "Potential integer overflow detected with function argument.",
                    "overflow",
                    "high",
                    get_line_number(arg),
                )


def analyze_underflow_in_node(node):
    if isinstance(node, (astnodes.AddOp, astnodes.SubOp, astnodes.MultOp)):
        left_operand = node.left
        right_operand = node.right

        if isinstance(left_operand, astnodes.Number) and is_potential_underflow(
            left_operand.n
        ):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with left operand.",
                "underflow",
                "high",
                get_line_number(left_operand),
            )

        if isinstance(right_operand, astnodes.Number) and is_potential_underflow(
            right_operand.n
        ):
            add_vulnerability(
                "Integer Underflow",
                "Potential integer underflow detected with right operand.",
                "underflow",
                "high",
                get_line_number(right_operand),
            )

    if isinstance(node, astnodes.LocalAssign):
        for value in node.values:
            if isinstance(value, astnodes.Number) and is_potential_underflow(value.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with local variable assignment.",
                    "underflow",
                    "high",
                    get_line_number(value),
                )

    if isinstance(node, astnodes.Function):
        for arg in node.args:
            if isinstance(arg, astnodes.Number) and is_potential_underflow(arg.n):
                add_vulnerability(
                    "Integer Underflow",
                    "Potential integer underflow detected with function argument.",
                    "underflow",
                    "high",
                    get_line_number(arg),
                )


def analyze_overflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_overflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_overflow_in_node(body_node)

            if node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(
                                ret_val, astnodes.Number
                            ) and is_potential_overflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Overflow",
                                    f"Potential integer overflow detected in return statement of function '{node.name.id}'.",
                                    "overflow",
                                    "high",
                                    get_line_number(ret_val),
                                )


def analyze_underflow_and_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        analyze_underflow_in_node(node)

        if isinstance(node, astnodes.Function):
            for body_node in ast.walk(node.body):
                analyze_underflow_in_node(body_node)

            if node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(
                                ret_val, astnodes.Number
                            ) and is_potential_underflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Underflow",
                                    f"Potential integer underflow detected in return statement of function '{node.name.id}'.",
                                    "underflow",
                                    "high",
                                    get_line_number(ret_val),
                                )


def analyze_return(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            has_return = any(isinstance(n, astnodes.Return) for n in node.body.body)
            if not has_return:
                add_vulnerability(
                    "Missing Return Statement",
                    "A function is missing a return statement.",
                    "missing_return",
                    "low",
                    get_line_number(node),
                )


def check_private_key_exposure(code):
    tree = ast.parse(code)
    private_key_words = [
        "privatekey",
        "private_key",
        "secretkey",
        "secret_key",
        "keypair",
        "key_pair",
        "api_key",
    ]

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if (
                    isinstance(target, astnodes.Name)
                    and target.id.lower() in private_key_words
                ):
                    add_vulnerability(
                        "Private Key Exposure",
                        f"Potential exposure of private key in variable '{target.id}'.",
                        "private_key_exposure",
                        "high",
                        get_line_number(node),
                    )


def analyze_reentrancy(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return (
            isinstance(node, astnodes.Call)
            and isinstance(node.func, astnodes.Name)
            and node.func.id == "external_call"
        )

    def has_state_change(node):
        return isinstance(node, astnodes.Assign)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, n in enumerate(body):
                if is_external_call(n):
                    for subsequent_node in body[i + 1 :]:
                        if has_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy",
                                "A function calls an external contract before updating its state.",
                                "external_call",
                                "high",
                                get_line_number(node),
                            )


def analyze_floating_pragma(code):
    deprecated_functions = ["setfenv", "getfenv"]
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id in deprecated_functions:
                add_vulnerability(
                    "Floating Pragma",
                    f"Floating pragma issue detected with function '{node.func.id}'.",
                    "floating_pragma",
                    "low",
                    get_line_number(node),
                )


def analyze_denial_of_service(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            if node.func.id == "perform_expensive_operation":
                add_vulnerability(
                    "Denial of Service",
                    f"Potential Denial of Service vulnerability detected with function '{node.func.id}'.",
                    "denial_of_service",
                    "medium",
                    get_line_number(node),
                )


def analyze_unchecked_external_calls(code):
    tree = ast.parse(code)

    def is_external_call(node):
        return (
            isinstance(node, astnodes.Call)
            and isinstance(node.func, astnodes.Index)
            and isinstance(node.func.value, astnodes.Name)
        )

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for n in node.body.body:
                if is_external_call(n):
                    add_vulnerability(
                        "Unchecked External Calls",
                        f"Unchecked external call detected in function '{node.name.id}'.",
                        "unchecked_external_call",
                        "medium",
                        get_line_number(n),
                    )


def analyze_greedy_suicidal_functions(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            for n in node.body.body:
                if (
                    isinstance(n, astnodes.Call)
                    and isinstance(n.func, astnodes.Name)
                    and n.func.id == "transfer_funds"
                ):
                    if not any(
                        isinstance(subsequent_node, astnodes.Return)
                        for subsequent_node in node.body.body
                    ):
                        add_vulnerability(
                            "Greedy Function",
                            f"Greedy function detected without a return statement in function '{node.name.id}'.",
                            "greedy_function",
                            "high",
                            get_line_number(n),
                        )


def analyze_lua_code(code):
    global vulnerabilities
    vulnerabilities = []
    analyze_overflow_and_return(code)
    analyze_underflow_and_return(code)
    analyze_return(code)
    check_private_key_exposure(code)
    analyze_reentrancy(code)
    analyze_floating_pragma(code)
    analyze_denial_of_service(code)
    analyze_unchecked_external_calls(code)
    analyze_greedy_suicidal_functions(code)
    return vulnerabilities




@app.route("/analyze", methods=["POST"])
def analyze():
    code = request.form.get("code")
    if not code:
        return "No code provided", 400

    vulnerabilities = analyze_lua_code(code)
    return jsonify(vulnerabilities)

@app.route('/')
def home():
    return '''
<!DOCTYPE html>
<html>
<head>
    <script src="https://cdn.tailwindcss.com"></script>
    <title>SAM</title>
    <!-- CodeMirror CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.css">
    <!-- CodeMirror Theme (optional) -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/theme/material-darker.min.css">
    <!-- CodeMirror JS -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/mode/lua/lua.min.js"></script>
</head>
<body class="bg-gradient-to-r from-blue-400 via-blue-200 to-blue-500 min-h-screen flex flex-col font-mono">

<nav class="bg-white shadow-md">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <div class="flex items-center justify-between h-16">
      <div class="flex justify-center flex-1">
        <a href="https://sam-support.arweave.net/" class="text-gray-900 hover:bg-gray-200 px-3 py-2 rounded-md text-2xl font-medium">Security Auditing Monitoring</a>
      </div>
      <div class="flex items-center">
        <div class="ml-4 flex items-center">
          <div class="relative">
            <img class="h-10 w-10 md:h-12 md:w-12 rounded-full" src="static/images/logo.png" alt="Logo" id="dropdown-button">
            <div class="absolute right-2 mt-2 w-48 bg-white shadow-md text-center" id="dropdown-menu" style="display: none;">
              <a href="https://www.npmjs.com/package/sam-cli-npm" class="block px-4 py-2 text-gray-900 hover:bg-gray-200">📦 Check our npm package</a>
              <a href="https://pypi.org/project/sam-cli/" class="block px-4 py-2 text-gray-900 hover:bg-gray-200">🐍 Check our pypi package</a>
              <a href="https://github.com/krishvsoni/sam-API" class="block px-4 py-2 text-gray-900 hover:bg-gray-200">⭐️ Star on GitHub</a>
              <div class="block px-4 py-2 text-gray-900 "> -- samverse --</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</nav>

<div class="flex-grow flex items-center justify-center px-4 sm:px-6 lg:px-8">
    <div class="bg-white p-6 sm:p-8 rounded-lg shadow-md w-full max-w-4xl">
        <h1 class="text-xl sm:text-2xl font-bold mb-4">Enter Lua Code</h1>
        <form id="analyze-form" action="/analyze" method="post">
            <textarea id="code" name="code" rows="20" cols="80" class="w-full p-2 border rounded-md"></textarea><br>
            <div class="flex justify-between mt-4">
                <button type="submit" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Analyze</button>
                <a href="/cells" class="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded">Go to Cells</a>
            </div>
        </form>
        <div id="results" class="mt-8"></div>
    </div>
</div>

    
    <script>
    document.getElementById('dropdown-button').addEventListener('click', function() {
  var dropdownMenu = document.getElementById('dropdown-menu');
  if (dropdownMenu.style.display === 'none') {
    dropdownMenu.style.display = 'block';
  } else {
    dropdownMenu.style.display = 'none';
  }
});
        document.addEventListener('DOMContentLoaded', function () {
            var editor = CodeMirror.fromTextArea(document.getElementById('code'), {
                mode: 'lua',
                theme: 'material-darker',
                lineNumbers: true
            });

            const form = document.getElementById('analyze-form');
            const resultsContainer = document.getElementById('results');

            form.addEventListener('submit', async function (event) {
                event.preventDefault();
                const code = editor.getValue();
                const formData = new FormData();
                formData.append('code', code);

                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });

                const vulnerabilities = await response.json();

                resultsContainer.innerHTML = `
                    <h2 class="text-xl font-bold">Vulnerabilities Found:</h2>
                    <ul class="list-disc list-inside">
                        ${vulnerabilities.map(vul => `
                            <li>
                                <strong>${vul.name}</strong>: ${vul.description} (Severity: ${vul.severity}, Line: ${vul.line})
                            </li>
                        `).join('')}
                    </ul>
                `;
            });
        });
    </script>
</body>
</html>
    '''
@app.route("/analyzecells", methods=["POST"])
def analyze_cells():
    code_cells = request.json.get("code_cells", [])
    results = []

    for cell in code_cells:
        cell_vulnerabilities = []
        global vulnerabilities
        vulnerabilities = []

        try:
            analyze_overflow_and_return(cell)
            analyze_underflow_and_return(cell)
            analyze_return(cell)
            check_private_key_exposure(cell)
            analyze_reentrancy(cell)
            analyze_floating_pragma(cell)
            analyze_denial_of_service(cell)
            analyze_unchecked_external_calls(cell)
            analyze_greedy_suicidal_functions(cell)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        if vulnerabilities:
            cell_vulnerabilities.extend(vulnerabilities)

        results.append({"code_cell": cell, "vulnerabilities": cell_vulnerabilities})

    return jsonify(results)


@app.route("/cells")
def cells():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sam</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/codemirror@5.65.6/lib/codemirror.css">
    <style>
        .CodeMirror {
            border: 1px solid #ddd;
            height: auto;
        }
        .cm-s-material-darker {
            background-color: #263238;
            color: #c3c7cb;
        }
    </style>
    <nav class="bg-white shadow-md font-mono">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex justify-center flex-1">
                    <a href="https://sam-support.arweave.net/" class="text-gray-900 hover:bg-gray-200 px-3 py-2 rounded-md text-2xl font-medium">Security Auditing Monitoring</a>
                </div>
                <div class="flex items-center">
                    <div class="ml-4 flex items-center">
                        <img class="h-10 w-10 md:h-12 md:w-12 rounded-full" src="static/images/logo.png" alt="Logo">
                    </div>
                </div>
            </div>
        </div>
    </nav>
</head>
<body class="bg-gradient-to-r from-blue-200 via-blue-200 to-blue-300 min-h-screen flex flex-col font-mono">
    <div class="container mx-auto p-7">
        <div class="bg-white p-6 sm:p-8 rounded-lg shadow-md w-full max-w-8xl">
            <h1 class="text-xl sm:text-2xl font-bold mb-4">Lua Code Cell</h1>
            <div id="code-cell-container"></div>
            <button id="add-code-cell" class="mt-4 bg-blue-500 text-white py-2 px-4 rounded">Add Code Cell</button>
            <button id="analyze-code" class="mt-4 ml-2 bg-green-500 text-white py-2 px-4 rounded">Analyze Code</button>
            <div id="results" class="mt-8"></div>
            <button id="download-json" class="mt-4 bg-red-500 text-white py-2 px-4 rounded hidden">Download JSON</button>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.6/lib/codemirror.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.6/mode/lua/lua.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const codeCellContainer = document.getElementById('code-cell-container');
            const addCodeCellButton = document.getElementById('add-code-cell');
            const analyzeCodeButton = document.getElementById('analyze-code');
            const downloadJsonButton = document.getElementById('download-json');
            const resultsContainer = document.getElementById('results');
            let codeMirrors = [];

            function createCodeCell() {
                const codeCellDiv = document.createElement('div');
                codeCellDiv.classList.add('mb-4');
                const codeMirrorElement = document.createElement('textarea');
                codeCellDiv.appendChild(codeMirrorElement);
                codeCellContainer.appendChild(codeCellDiv);

                const codeMirror = CodeMirror.fromTextArea(codeMirrorElement, {
                    mode: 'lua',
                    theme: 'material-darker',
                    lineNumbers: true
                });
                codeMirrors.push(codeMirror);
            }

            addCodeCellButton.addEventListener('click', () => {
                createCodeCell();
            });

            analyzeCodeButton.addEventListener('click', async () => {
                const codeCells = codeMirrors.map(cm => cm.getValue());
                const response = await fetch('/analyzecells', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code_cells: codeCells })
                });
                const results = await response.json();

                resultsContainer.innerHTML = '';
                results.forEach((result, index) => {
                    const resultDiv = document.createElement('div');
                    resultDiv.classList.add('mb-4');
                    resultDiv.innerHTML = `
                        <h2 class="text-xl font-bold">Code Cell ${index + 1}</h2>
                        <pre class="bg-gray-200 p-2">${result.code_cell}</pre>
                        <h3 class="text-lg font-bold">Vulnerabilities:</h3>
                        <ul class="list-disc list-inside">
                            ${result.vulnerabilities.map(vul => `
                                <li>
                                    <strong>${vul.name}</strong>: ${vul.description} (Severity: ${vul.severity}, Line: ${vul.line})
                                </li>
                            `).join('')}
                        </ul>
                    `;
                    resultsContainer.appendChild(resultDiv);
                });

                // Show the download button and attach click handler
                downloadJsonButton.classList.remove('hidden');
                downloadJsonButton.onclick = () => {
                    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'vulnerabilities.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                };
            });

            createCodeCell();
        });
    </script>
</body>
</html>


"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
