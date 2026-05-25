#!/bin/bash
# --- MIRAGE ORACLE INSTALLER ---

echo "Installation de Mirage Oracle..."

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
# Oracle utilise principalement les données partagées, peu de dépendances lourdes au début
pip install pyyaml

echo "[+] Installation terminée."
