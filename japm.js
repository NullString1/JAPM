class User {
    #username;
    #password_hash;
    #credentials = [];
    #created_at;

    constructor(username, password_hash=null, password=null) {
        this.#username = username;
        if (password_hash == null && password != null) {
            this.setPassword(password);
        } else if (password_hash != null) {
            this.#password_hash = password_hash;
        } else {
            throw new Error("Either password hash or password must be provided.");
        }
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
            password_hash: Crypt.toHex(this.#password_hash),
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
        console.log("Password hash: " + Array.from(new Uint8Array(password_hash)).map(b => b.toString(16)).join(""));
        const algo = { name: "AES-CBC", iv: crypto.getRandomValues(new Uint8Array(16)) };
        return Crypt.keyFromPassword(password_hash).then((k) => {
            return crypto.subtle.encrypt(algo, k.key, new TextEncoder().encode(data)).then(encrypted => {
                return { data: Crypt.toHex(encrypted), iv: Crypt.toHex(algo.iv), salt: Crypt.toHex(k.salt) };
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

    static toUint8Array(hex) {
        return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    }

    static toHex(uint8) {
        return (new Uint8Array(uint8)).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
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
        const fileinput = $("#load-input")[0];
        if (fileinput.files.length === 0) {
            this.#user = new User(username, null, password);
            this.updateState(JAPM.State.AUTHENTICATED);
        } else {
            const file = fileinput.files[0];
            const reader = new FileReader();
            reader.onload = () => {
                const data = JSON.parse(reader.result);
                data.data = Crypt.toUint8Array(data.data);
                data.iv = Crypt.toUint8Array(data.iv);
                data.salt = Crypt.toUint8Array(data.salt);
                crypto.subtle.digest('SHA-256', new TextEncoder().encode(password)).then(hash => {
                    console.log("Password hash: " + Array.from(new Uint8Array(hash)).map(b => b.toString(16)).join(""));
                    Crypt.decrypt(data, hash).then(decrypted => {
                        decrypted = JSON.parse(decrypted);
                        decrypted.password_hash = Crypt.toUint8Array(decrypted.password_hash);
                        decrypted.credentials = decrypted.credentials.map(c => JSON.parse(c));
                        const user = new User(decrypted.username, decrypted.password_hash, null);
                        user.setCredentials(decrypted.credentials.map(cred => new Credential(cred.username, cred.password, cred.url, cred.name)));
                        this.setUser(user);
                        if (this.#user.getUsername() === username) {
                            this.#user.checkPassword(password).then(res => {
                                if (res) {
                                    this.updateState(JAPM.State.AUTHENTICATED);
                                    return;
                                } else {
                                    console.log("Invalid password");
                                    $("#login-error").removeClass("d-none");
                                    return;
                                }
                            });
                        } else {
                            console.log("Invalid username");
                            $("#login-error").removeClass("d-none");
                            return;
                        }
                    }).catch(e => {
                        console.error("Decryption failed.");
                        $("#login-error").removeClass("d-none");
                    });
                });
            };
            reader.readAsText(file);
        }
    }

    setupLogin() {
        $(document).ready(() => {
            $("#login-container").removeClass("d-none");
            $("#login-submit").click(() => {
                console.log("Login clicked");
                this.login($("#login-username").val(), $("#login-password").val());
            });
            $("#load-button").click(() => {
                $("#load-input").click();
            });
            $("#load-input").change(() => {
                $("#login-submit").text("Login");
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

document.japm = new JAPM();