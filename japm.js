class User {
    #username;
    #password_hash;
    #credentials = [];
    #created_at;

    constructor(username, password) {
        this.#username = username;
        this.setPassword(password);
        this.#created_at = new Date();
    }

    setPassword(password) {
        const buf = new TextEncoder().encode(password);
        crypto.subtle.digest('SHA-256', buf).then(h => {
            this.#password_hash = h;
        });
    }

    getUsername() {
        return this.#username;
    }

    checkPassword(password) {
        const buf = new TextEncoder().encode(password);
        return crypto.subtle.digest('SHA-256', buf).then(h => {
            const correct_hash = Array.from(new Uint8Array(this.#password_hash));
            const hash = Array.from(new Uint8Array(h));
            if (correct_hash.length !== hash.length) {
                return false;
            }
            for (let i = 0; i < correct_hash.length; i++) {
                if (correct_hash[i] !== hash[i]) {
                    return false;
                }
            }
            return true;
        });
    }

    getCredentials() {
        return this.#credentials;
    }

    setCredentials(credentials) {
        this.#credentials = credentials;
    }

    addCredential(credential) {
        this.#credentials.push(credential);
    }

    getCreatedAt() {
        return this.#created_at;
    }

    toJSON() {
        return JSON.stringify({
            username: this.#username,
            password_hash: new Uint8Array(this.#password_hash).map(b => b.toString(16)).join(""),
            created_at: this.#created_at,
            credentials: this.#credentials.map(cred => cred.toJSON())
        });
    }

    getPasswordHash() {
        return this.#password_hash;
    }
}

class Credential {
    #username;
    #password;
    #created_at;
    #last_modified_at;
    #url;
    #name;

    constructor(username, password, url, name) {
        this.#username = username;
        this.#password = password;
        this.#url = url;
        this.#name = name;
        this.#created_at = new Date();
        this.#last_modified_at = new Date();
    }

    getPassword() {
        return this.#password;
    }

    getUsername() {
        return this.#username;
    }

    setPassword(password) {
        this.#password = password;
        this.#last_modified_at = new Date();
    }

    setUsername(username) {
        this.#username = username;
        this.#last_modified_at = new Date();
    }

    getCreatedAt() {
        return this.#created_at;
    }

    getLastModAt() {
        return this.#last_modified_at;
    }

    getURL() {
        return this.#url;
    }

    setURL(url) {
        this.#url = url;
        this.#last_modified_at = new Date();
    }

    getName() {
        return this.#name;
    }

    setName(name) {
        this.#name = name;
        this.#last_modified_at = new Date();
    }

    toJSON() {
        return JSON.stringify({
            username: this.#username,
            password: this.#password,
            created_at: this.#created_at,
            last_modified_at: this.#last_modified_at,
            url: this.#url,
            name: this.#name
        });
    }
}

class FileHandler {
    loadFromFile(file) {
    }

    writeToFile(data) {
        const blob = new Blob([JSON.stringify(data)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "japm.json";
        a.click();
    }
}

class Crypt {
    static keyFromPassword(password_hash, salt_ = null) {
        // Hash the password, then import it, then derive a key from it with PBKDF2 for AES-CBC
        return crypto.subtle.importKey("raw", password_hash, { name: "PBKDF2" }, false, ["deriveKey"]).then(key => {
            const salt = salt_ == null ? crypto.getRandomValues(new Uint8Array(16)) : salt_;
            return crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: salt,
                    iterations: 100000,
                    hash: "SHA-256"
                },
                key,
                { name: "AES-CBC", length: 256 },
                false,
                ["encrypt", "decrypt"]
            ).then(derivedKey => {
                return { key: derivedKey, salt: salt };
            });
        });

    }

    static encrypt(data, password_hash) {
        const algo = { name: "AES-CBC", iv: crypto.getRandomValues(new Uint8Array(16)) };
        return Crypt.keyFromPassword(password_hash).then((k) => {
            return crypto.subtle.encrypt(algo, k.key, new TextEncoder().encode(data)).then(encrypted => {
                return { data: new Uint8Array(encrypted).map(b => b.toString(16)).join(""), iv: algo.iv.map(b => b.toString(16)).join(""), salt: k.salt.map(b => b.toString(16)).join("") };
            });
        });
    }

    static decrypt(data, password_hash) {
        const algo = { name: "AES-CBC", iv: data.iv };
        return Crypt.keyFromPassword(password_hash, data.salt).then(key => {
            return crypto.subtle.decrypt(algo, key.key, data.data).then(decrypted => {
                return new TextDecoder().decode(decrypted);
            });
        }).catch(e => {
            console.error("Incorrect password. Decryption failed.");
        });
    }
}

class JAPM {
    /** @type {User} */
    #user;
    #fileHandler;
    /** @type {JAPM.State} */
    #state;

    static State = {
        UNAUTHENTICATED: "unauthenticated",
        AUTHENTICATED: "authenticated"
    };

    constructor() {
        this.#fileHandler = new FileHandler();
        this.updateState(JAPM.State.UNAUTHENTICATED);
    }

    setUser(user) {
        this.#user = user;
    }

    updateState(state) {
        this.#state = state;
        switch (state) {
            case JAPM.State.UNAUTHENTICATED:
                this.setupLogin();
                break;
            case JAPM.State.AUTHENTICATED:
                this.setupMainView();
                break;
        }

    };

    login(username, password) {
        if (this.#user != undefined && this.#user.getUsername() === username) {
            this.#user.checkPassword(password).then(res => {
                if (res) {
                    this.updateState(JAPM.State.AUTHENTICATED);
                } else {
                    console.log("Invalid password");
                    $("#login-error").removeClass("d-none");
                }
            });
        } else {
            console.log("Invalid username");
            $("#login-error").removeClass("d-none");
        }
    }

    setupLogin() {
        $(document).ready(() => {
            $("#login-container").removeClass("d-none");
            $("#login-submit").click(() => {
                console.log("Login clicked");
                this.login($("#login-username").val(), $("#login-password").val());
            });
        });
    }

    setupMainView() {
        $(document).ready(() => {
            $("#login-container").addClass("d-none");
            $("#main-container").removeClass("d-none");
            this.buildCredsTable();
            $("#add-cred-submit").click(() => {
                const name = $("#name").val();
                const site = $("#site").val();
                const username = $("#username").val();
                const password = $("#password").val();
                if (name === "" || site === "" || username === "" || password === "") {
                    return;
                }
                this.addCred(
                    name,
                    site,
                    username,
                    password
                );
            });
            $("#save-button").click(() => {
                this.exportData();
            });
        });
    }

    buildCredsTable() {
        if (this.#user == undefined) {
            this.updateState(JAPM.State.UNAUTHENTICATED);
            return;
        }
        const tableBody = $("#creds-table tbody");
        tableBody.empty();
        this.#user.getCredentials().forEach((/** @type {Credential} */cred) => {
            tableBody.append(
                `<tr>
                <td>${cred.getName()}</td>
                <td>${cred.getURL()}</td>
                <td>${cred.getUsername()}</td>
                <td>${cred.getPassword()}</td>
                <td>${cred.getCreatedAt().toGMTString()}</td>
                <td>${cred.getLastModAt().toGMTString()}</td>
            </tr>`
            );
        });
    }

    addCred(name, url, username, password) {
        this.#user.addCredential(new Credential(username, password, url, name));
        this.buildCredsTable();
    }

    exportData() {
        const data = this.#user.toJSON();
        Crypt.encrypt(data, this.#user.getPasswordHash()).then(encrypted => {
            this.#fileHandler.writeToFile(encrypted);
        });
    }

}

document.user = new User("u", "p");
document.japm = new JAPM();
document.japm.setUser(document.user);
document.user.addCredential(new Credential("user1", "pass1", "example.com", "example"));
