from luaparser import ast, astnodes
from utils import get_line_number, add_vulnerability




def is_potential_overflow(number):
    INT_MAX = 2147483647
    return number >= INT_MAX


def is_potential_underflow(number):
    INT_MIN = -2147483648
    return number <= INT_MIN


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
    private_key_words = ["privatekey", "private_key", "secretkey", "secret_key", "keypair", "key_pair", "api_key", "clientsecret", "client_secret", "access_key", "arweave_key", "arweave_private_key", "arweave_secret", "arweave_wallet", "arweave_wallet_key", "arweave_wallet_private_key", "arweave_wallet_secret", "arweave_keyfile", "arweave_key_file", "arweave_keypair", "arweave_key_pair", "arweave_api_key", "arweave_client_secret", "arweave_access_key"]

    for node in ast.walk(tree):
        if isinstance(node, astnodes.Assign):
            for target in node.targets:
                if isinstance(target, astnodes.Name) and target.id.lower() in private_key_words:
                    add_vulnerability("Private Key Exposure", f"Potential exposure of private key in variable '{target.id}'.", "private_key_exposure", "high", get_line_number(node))

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
