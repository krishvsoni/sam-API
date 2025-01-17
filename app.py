from flask import Flask, render_template, request, jsonify
from luaparser import ast, astnodes
from luaparser.astnodes import *
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

            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_overflow(ret_val.n):
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

            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                for n in node.body.body:
                    if isinstance(n, astnodes.Return):
                        for ret_val in n.values:
                            if isinstance(ret_val, astnodes.Number) and is_potential_underflow(ret_val.n):
                                add_vulnerability(
                                    "Integer Underflow",
                                    f"Potential integer underflow detected in return statement of function '{node.name.id}'.",
                                    "underflow",
                                    "high",
                                    get_line_number(ret_val),)


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
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair", "api_key", "clientsecret", "client_secret", "access_key", "arweave_key", "arweave_private_key", "arweave_secret", "arweave_wallet", "arweave_wallet_key", "arweave_wallet_private_key", "arweave_wallet_secret", "arweave_keyfile", "arweave_key_file", "arweave_keypair", "arweave_key_pair", "arweave_api_key", "arweave_client_secret", "arweave_access_key"]


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
def get_code_and_vulnerable_lines(code, vulnerabilities):
    # Total lines
    total_lines = len(code.splitlines())
    
    # Vulnerable lines (extract unique line numbers from vulnerabilities)
    vulnerable_lines = {vuln["line"] for vuln in vulnerabilities if "line" in vuln}
    num_vulnerable_lines = len(vulnerable_lines)
    
    return total_lines, num_vulnerable_lines

# new function to analyze lua code

def analyze_access_control(code):
    """
    Analyzes Lua code for access control issues, particularly in sensitive functions like mint and burn.
    """
    tree = ast.parse(code)

    def has_access_control(node):
        """
        Check if the node contains access control logic, e.g., checking owner or caller.
        """
        if isinstance(node, astnodes.If):
            for condition in ast.walk(node.test):
                if isinstance(condition, astnodes.Name) and condition.id in ["owner", "caller"]:
                    return True
        return False

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            function_name = node.name.id if isinstance(node.name, astnodes.Name) else None
            if function_name in ["mint", "burn"]:
                access_control_found = False
                for body_node in ast.walk(node.body):
                    if has_access_control(body_node):
                        access_control_found = True
                        break
                if not access_control_found:
                    severity = "high" if function_name in ["mint", "burn"] else "medium"
                    add_vulnerability(
                        "Access Control Issue",
                        f"Missing access control check in sensitive function '{function_name}'.",
                        "access_control",
                        severity,
                        get_line_number(node),
                    )

def is_critical_state_change(node):
    return (
        isinstance(node, astnodes.Assign)
        or (
            isinstance(node, astnodes.Call)
            and isinstance(node.func, astnodes.Name)
            and node.func.id.lower() in ["mint", "burn", "transfer"]
        )
    )
def is_error_handling_missing(node):
    has_error_handling = any(
        isinstance(stmt, astnodes.TryExcept) or isinstance(stmt, astnodes.PCall)
        for stmt in node.body.body
    )
    return not has_error_handling

def analyze_unhandled_errors_in_handlers(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            if isinstance(node.name, astnodes.Name) and node.name.id == "another_example":
                body = node.body.body
                for stmt in body:
                    if is_critical_state_change(stmt) and is_error_handling_missing(node):
                        add_vulnerability(
                            "Unhandled Errors in Handlers",
                            f"Unhandled errors in function '{node.name.id}' where critical state changes occur.",
                            "unhandled_errors",
                            "high",
                            get_line_number(stmt),
                        )


def analyze_reentrancy_in_handlers(code):
    tree = ast.parse(code)

    def is_state_change(node):
        return isinstance(node, astnodes.Assign) or (
            isinstance(node, astnodes.Call) and node.func.id.lower() in ["mint", "burn"]
        )

    def is_external_call(node):
        # Check if the node is a Call node
        if isinstance(node, astnodes.Call):
            # If the function is a simple Name node (e.g., msg.reply or ao.send)
            if isinstance(node.func, astnodes.Name):
                return node.func.id.lower() in ["msg.reply", "ao.send"]
            # If the function is an Index node (e.g., obj["key"])
            elif isinstance(node.func, astnodes.Index):
                # Check if the value part of the index is a Name node
                if isinstance(node.func.value, astnodes.Name):
                    return node.func.value.id.lower() in ["msg.reply", "ao.send"]
        return False

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Function):
            body = node.body.body
            for i, stmt in enumerate(body):
                if is_external_call(stmt):
                    for subsequent_node in body[i + 1:]:
                        if is_state_change(subsequent_node):
                            add_vulnerability(
                                "Reentrancy in Handlers",
                                f"Reentrancy vulnerability in function '{node.name.id}' where state changes follow external calls.",
                                "reentrancy",
                                "high",
                                get_line_number(stmt),
                            )




def analyze_improper_balance_checks(code):
    tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Call) and isinstance(node.func, astnodes.Name):
            # Check for improper usage of balance operations
            if node.func.id in ["add", "subtract"]:
                args = node.args
                if len(args) == 2 and all(isinstance(arg, astnodes.Name) for arg in args):
                    if any(
                        arg.id.lower() in ["balances[msg.from]", "balances[msg.recipient]"]
                        for arg in args
                    ):
                        add_vulnerability(
                            "Improper Balance Checks",
                            f"Potential improper balance check in function '{node.func.id}'.",
                            "improper_balance_check",
                            "high",
                            get_line_number(node),
                        )

            # Check for negative balances or improper handling
            if (
                node.func.id in ["add", "subtract"]
                and any(isinstance(arg, astnodes.Number) and arg.n < 0 for arg in node.args)
            ):
                add_vulnerability(
                    "Negative Balances",
                    "Negative balance detected in a critical operation.",
                    "negative_balance",
                    "medium",
                    get_line_number(node),
                )

def analyze_replay_attacks(code):
    """
    Analyzes Lua code to detect replay attack vulnerabilities.
    Checks for missing unique tracking mechanisms (msg.Id or timestamps)
    and the absence of history verification for processed requests.
    """
    tree = ast.parse(code)

    has_processed_table = False
    has_replay_protection = False

    for node in ast.walk(tree):
        if (
            isinstance(node, astnodes.Assign)
            and isinstance(node.targets[0], astnodes.Name)
            and node.targets[0].id.lower() in ["processed_messages", "processed_ids"]
        ):
            has_processed_table = True

        if (
            isinstance(node, astnodes.If)
            and isinstance(node.test, astnodes.Index)
            and isinstance(node.test.value, astnodes.Name)
            and node.test.value.id.lower() in ["processed_messages", "processed_ids"]
        ):
            if isinstance(node.test.idx, astnodes.Name) and node.test.idx.id == "msg.Id":
                has_replay_protection = True

    if not has_processed_table:
        add_vulnerability(
            "Replay Attack",
            "No processed message table (e.g., processedMessages) to track processed requests.",
            "replay_attack",
            "high",
            0,  
        )

    if has_processed_table and not has_replay_protection:
        add_vulnerability(
            "Replay Attack",
            "Processed table exists but lacks replay protection mechanism for msg.Id.",
            "replay_attack",
            "medium",
            0,  
        )



def analyze_state_reset_misuse(code):
    """
    Analyzes Lua code for misuse of the ResetState flag.
    Detects:
    1. Unrestricted access to ResetState.
    2. Arbitrary toggling of ResetState in production.
    """
    tree = ast.parse(code)
    vulnerabilities = []

    for node in ast.walk(tree):
        if isinstance(node, Assign) and any(
            isinstance(target, Name) and target.id == "ResetState"
            for target in node.targets
        ):
            if not any(
                isinstance(parent, If)
                and any(
                    isinstance(cond, Name) and cond.id in ["isAdmin", "isTrusted"]
                    for cond in ast.walk(parent.test)
                )
                for parent in ast.walk(tree)
            ):
                vulnerabilities.append({
                    "type": "State Reset Misuse",
                    "message": "ResetState is toggled without access control.",
                    "severity": "high",
                    "line": getattr(node, "lineno", None),
                })

        if isinstance(node, Call) and isinstance(node.func, Name) and node.func.id == "resetBalances":
            if not any(
                isinstance(parent, If)
                and any(
                    isinstance(cond, Name) and cond.id in ["isTrusted", "isAdmin"]
                    for cond in ast.walk(parent.test)
                )
                for parent in ast.walk(tree)
            ):
                vulnerabilities.append({
                    "type": "Critical State Reset",
                    "message": "Critical reset operation performed without safeguard.",
                    "severity": "medium",
                    "line": getattr(node, "lineno", None),
                })

    return vulnerabilities


# def analyze_tag_handling_security(code):
#     """
#     Analyzes Lua code to detect vulnerabilities in tag handling.
#     Specifically checks for:
#     1. Overwriting of critical keys by tags starting with "X-".
#     2. Lack of sanitization or validation of tags starting with "X-".
#     """
#     if not code.strip():
#         raise ValueError("Lua code is empty or invalid.")
    
#     try:
#         tree = ast.parse(code)
#     except luaparser.builder.SyntaxException as e:
#         raise ValueError(f"Syntax error while parsing Lua code: {str(e)}")

#     vulnerabilities = []

#     critical_keys = ["userData", "session", "config", "admin"]

#     for node in ast.walk(tree):
#         if isinstance(node, Assign):
#             for target in node.targets:
#                 if isinstance(target, Index) and isinstance(target.idx, String):
#                     tag_name = target.idx.s
#                     if tag_name.startswith("X-"):  
#                         if any(critical_key in tag_name for critical_key in critical_keys):
#                             vulnerabilities.append({
#                                 "type": "Tag Handling Security",
#                                 "message": f"Tag '{tag_name}' starts with 'X-' and may overwrite a critical key.",
#                                 "severity": "high",
#                                 "line": getattr(node, "lineno", None),
#                             })

#                         if not any(
#                             isinstance(stmt, Call) and isinstance(stmt.func, Name) and stmt.func.id == "sanitizeTag"
#                             for stmt in ast.walk(tree)
#                         ):
#                             vulnerabilities.append({
#                                 "type": "Tag Handling Security",
#                                 "message": f"Tag '{tag_name}' starting with 'X-' is not sanitized.",
#                                 "severity": "high",
#                                 "line": getattr(node, "lineno", None),
#                             })
    
#     return vulnerabilities




def analyze_lua_code(code):
    global vulnerabilities
    vulnerabilities = []
    # analyze_tag_handling_security(code)
    analyze_state_reset_misuse(code)
    # analyze_replay_attacks(code)
    analyze_improper_balance_checks(code)
    analyze_reentrancy_in_handlers(code)
    analyze_unhandled_errors_in_handlers(code)
    analyze_access_control(code)
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
    total_lines, num_vulnerable_lines = get_code_and_vulnerable_lines(code, vulnerabilities)

    # Check if any vulnerabilities were found
    # if not vulnerabilities:
    #     return jsonify({"message": "No vulnerabilities found."}), 200
    
    # return jsonify(vulnerabilities)
    if not vulnerabilities:
        return jsonify({
            "message": "No vulnerabilities found.",
            "total_lines": total_lines,
            "vulnerable_lines": num_vulnerable_lines
        })
    
    return jsonify({
        "vulnerabilities": vulnerabilities,
        "total_lines": total_lines,
        "vulnerable_lines": num_vulnerable_lines
    })
@app.route('/')
def home():
    return render_template('index.html')

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
    return render_template("cells.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
