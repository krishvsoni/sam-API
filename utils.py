def get_line_number(node):
    if hasattr(node, "line") and node.line is not None:
        return node.line
    if hasattr(node, "_parent"):
        return get_line_number(node._parent)
    return None


def add_vulnerability(name, description, pattern, severity, line):
    return {
        "name": name,
        "description": description,
        "pattern": pattern,
        "severity": severity,
        "line": line,
    }