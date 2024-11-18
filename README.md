# README

## Overview

This application provides routes for analyzing Lua code for vulnerabilities. The application includes a web interface with two primary functionalities:
1. Analyzing a single block of Lua code.
2. Analyzing multiple blocks of Lua code (code cells).

## Routes

### 1. Analyze Single Lua Code Block

#### Route
`POST /analyze`

#### Description
Analyzes a single block of Lua code for vulnerabilities.

#### Request Body
The request should include a form field named `code` containing the Lua code to be analyzed.

##### Example
```bash
curl -X POST http://localhost:5000/analyze -F "code=YOUR_LUA_CODE_HERE"
```

#### Response
The response will be a JSON object containing a list of identified vulnerabilities.

##### Example
```json
[
    {
        "name": "VulnerabilityName",
        "description": "Description of the vulnerability",
        "severity": "Severity level",
        "line": 10
    }
]
```

### 2. Analyze Multiple Lua Code Cells

#### Route
`POST /analyzecells`

#### Description
Analyzes multiple blocks of Lua code (code cells) for vulnerabilities.

#### Request Body
The request should include a JSON object with an array of code cells under the key `code_cells`.

##### Example
```json
{
    "code_cells": [
        "YOUR_LUA_CODE_CELL_1",
        "YOUR_LUA_CODE_CELL_2"
    ]
}
```

##### Example with cURL
```bash
curl -X POST http://localhost:5000/analyzecells -H "Content-Type: application/json" -d '{
    "code_cells": [
        "YOUR_LUA_CODE_CELL_1",
        "YOUR_LUA_CODE_CELL_2"
    ]
}'
```

#### Response
The response will be a JSON object containing the original code cells and their identified vulnerabilities.

##### Example
```json
[
    {
        "code_cell": "YOUR_LUA_CODE_CELL_1",
        "vulnerabilities": [
            {
                "name": "VulnerabilityName",
                "description": "Description of the vulnerability",
                "severity": "Severity level",
                "line": 10
            }
        ]
    },
    {
        "code_cell": "YOUR_LUA_CODE_CELL_2",
        "vulnerabilities": []
    }
]
```

### 3. Home Page

#### Route
`GET /`

#### Description
Serves the home page where users can input Lua code and analyze it for vulnerabilities.

### 4. Code Cells Page

#### Route
`GET /cells`

#### Description
Serves the page where users can input multiple blocks of Lua code (code cells) and analyze them for vulnerabilities.

## Running the Application

To run the application, ensure you have Flask installed and execute the following command in your terminal:

```bash
python app.py
```

The application will be accessible at `http://0.0.0.0:5000`.

## Dependencies

- [Flask-Wiz](https://pypi.org/project/flask-wiz/)
- [Tailwind CSS](https://tailwindcss.com/)
- [CodeMirror](https://codemirror.net/)


## Notes

- Ensure you have the necessary analysis functions (`analyze_overflow_and_return`, `analyze_underflow_and_return`, etc.) properly defined and imported in your application.
- The application assumes that static assets like the logo image are located in the `static/images/` directory.

## License

This project is licensed under the MIT License.

## Contact

For any inquiries or support, please contact [connectsentio@gmail.com].
