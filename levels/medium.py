from luaparser import astnodes,ast
from utils import get_line_number, add_vulnerability

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
