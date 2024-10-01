module.exports = {
    "env": {
        "browser": true,
        "es2021": true,
        "jasmine": true
    },
    "extends": "eslint:recommended",
    "overrides": [
        {
            "env": {
                "node": true
            },
            "files": [
                ".eslintrc.{js,cjs}"
            ],
            "parserOptions": {
                "sourceType": "script"
            }
        }, {
          "files": "*.json",
          "parser": "jsonc-eslint-parser",
          "rules": {}
        }
    ],
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module"
    },
    "rules": {
    }
}
