# Offensive-extractor-DB

🚀 Utilisation

Menu interactif

```bash
python3 offensive_extractor.py
```

CLI

```bash
# Mode hybrid (défaut) sur toutes les phases
python3 offensive_extractor.py http://target.local

# Mode stealth + phases 1,2,3
python3 offensive_extractor.py http://target.local --mode stealth --phases 1,2,3

# Cible avec login custom
python3 offensive_extractor.py http://target.local \
    --phases all \
    --login-path /api/v2/auth \
    --username-field email \
    --password-field pass
```
