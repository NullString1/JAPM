class User {
    #username;
    #password_hash;
    #credentials = [];
    #created_at;
    #generator_history = [];

    constructor(username, password_hash = null, password = null) {
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

    removeCredential(credential) {
        this.#credentials = this.#credentials.filter(cred => cred !== credential);
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
            credentials: this.#credentials.map(cred => cred.toJSON()),
            generator_history: this.#generator_history
        });
    }

    getPasswordHash() {
        return this.#password_hash;
    }

    getGeneratorHistory() {
        return this.#generator_history;
    }

    addGeneratorHistory(item) {
        this.#generator_history.push(item);
    }

    setGeneratorHistory(history) {
        this.#generator_history = history;
        this.#generator_history.forEach(item => {
            item.date = new Date(item.date);
        });
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
        a.download = `japm${new Date().toISOString()}.json`;
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

    static decryptBlob(data, password) {
        data.data = Crypt.toUint8Array(data.data);
        data.iv = Crypt.toUint8Array(data.iv);
        data.salt = Crypt.toUint8Array(data.salt);
        return crypto.subtle.digest('SHA-256', new TextEncoder().encode(password)).then(hash => {
            return Crypt.decrypt(data, hash).then(decrypted => {
                const decryptedData = JSON.parse(decrypted);
                decryptedData.password_hash = Crypt.toUint8Array(decryptedData.password_hash);
                decryptedData.credentials = decryptedData.credentials.map(c => {
                    const cred = JSON.parse(c);
                    return new Credential(cred.username, cred.password, cred.url, cred.name);
                });
                return decryptedData;
            }).catch(() => {
                console.error("Decryption of blob failed.");
            });
        });
    }

    static toUint8Array(hex) {
        return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    }

    static toHex(uint8) {
        return (new Uint8Array(uint8)).reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
    }
}

class PasswordGenerator {
    static generate(length, charset, user) {
        let password = "";
        const randValues = crypto.getRandomValues(new Uint32Array(length));
        randValues.forEach(v => {
            password += charset[v % charset.length];
        });
        user.addGeneratorHistory({ date: new Date(), password: password });
        return password
    }
}

class JAPM {
    /** @type {User} */
    #user;
    #fileHandler;
    /** @type {JAPM.State} */
    state;

    static State = {
        UNAUTHENTICATED: "unauthenticated",
        AUTHENTICATED: "authenticated"
    };

    constructor() {
        this.#fileHandler = new FileHandler();
        this.setupLogin();
        this.setupMainView();
        this.updateState(JAPM.State.UNAUTHENTICATED);
    }

    setUser(user) {
        this.#user = user;
    }

    updateState(state) {
        this.state = state;
        switch (state) {
            case JAPM.State.UNAUTHENTICATED:
                window.history.pushState({}, "", "#/login"); // Change URL to /login
                $("#login-container").removeClass("d-none");
                $("#main-container").addClass("d-none");
                if (localStorage.getItem("japm") != null) {
                    $("#login-submit").text("Login");
                    $("#reset-japm").removeClass("d-none");
                }
                break;
            case JAPM.State.AUTHENTICATED:
                window.history.pushState({}, "", "#/main"); // Change URL to /main 
                $("#login-container").addClass("d-none");
                $("#main-container").removeClass("d-none");
                this.buildCredsTable();
                break;
        }

    };

    login(username, password) {
        const fileinput = $("#load-input")[0];
        if (fileinput.files.length === 0) { // Fresh start or local storage
            if (localStorage.getItem("japm") == null) { // Complete fresh start
                this.#user = new User(username, null, password);
                const sInterval = setInterval(() => {
                    if (this.#user.getPasswordHash() != null) {
                        clearInterval(sInterval);
                        this.saveDataLS();
                    }
                }, 100);
                this.updateState(JAPM.State.AUTHENTICATED);
                return;
            }
            this.loadDataLS(username, password);
        } else { // Data loaded from backuo json file
            const file = fileinput.files[0];
            const reader = new FileReader();
            reader.onload = () => {
                const data = JSON.parse(reader.result);
                Crypt.decryptBlob(data, password).then(data => {
                    const user = new User(data.username, data.password_hash, null);
                    user.setCredentials(data.credentials);
                    this.setUser(user);
                    if (this.#user.getUsername() != username) {
                        console.log("Invalid username");
                        $("#login-error").removeClass("d-none");
                        return;
                    }
                    this.saveDataLS();
                    this.updateState(JAPM.State.AUTHENTICATED);
                }).catch((e) => {
                    console.error(e);
                    console.error("Invalid password");
                    $("#login-error").removeClass("d-none");
                });
            };
            reader.readAsText(file);
        };
    }

    setupLogin() {
        $("#login-submit").click(() => {
            this.login($("#login-username").val(), $("#login-password").val());
        });
        $("#load-button").click(() => {
            $("#load-input").click();
        });
        $("#load-input").change(() => {
            $("#login-submit").text("Login");
            bootstrap.Toast.getOrCreateInstance($("#data-loaded-toast")[0]).show();
        });
        $("#reset-data-button").click(() => {
            localStorage.removeItem("japm");
            $("#login-submit").text("Register");
            $("#reset-japm").addClass("d-none");
        });
        if (localStorage.getItem("japm") != null) {
            $("#login-submit").text("Login");
            $("#reset-japm").removeClass("d-none");
        }

    }

    setupMainView() {
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
        $("#logout-button").click(() => {
            this.#user = undefined;
            this.updateState(JAPM.State.UNAUTHENTICATED);
            $("#login-username").val("");
            $("#login-password").val("");
        });
        $("#gen-pass-submit").click(() => {
            const length = parseInt($("#gen-pass-length").val());
            const uppercase = $("#gen-pass-uppercase").is(":checked");
            const lowercase = $("#gen-pass-lowercase").is(":checked");
            const numbers = $("#gen-pass-numbers").is(":checked");
            const symbols = $("#gen-pass-symbols").is(":checked");
            let charset = "";
            if (uppercase) {
                charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            }
            if (lowercase) {
                charset += "abcdefghijklmnopqrstuvwxyz";
            }
            if (numbers) {
                charset += "0123456789";
            }
            if (symbols) {
                charset += "!@#$%^&*()_+-=[]{};':,.<>?";
            }
            if (charset === "") {
                return;
            }
            $("#gen-pass-span").text(PasswordGenerator.generate(length, charset, this.#user));
            this.saveDataLS();
        });
        $("#gen-pass-span").click(() => {
            navigator.clipboard.writeText($("#gen-pass-span").text()).then(() => {
                bootstrap.Toast.getOrCreateInstance($("#password-copied-toast")[0]).show();
            });
        });
        $("#gen-pass-history").click(() => {
            const modal = new bootstrap.Modal($("#gen-pass-history-modal")[0]);
            const table = $("#gen-pass-history-table tbody");
            table.empty();
            this.#user.getGeneratorHistory().reverse().forEach(item => {
                const tr = document.createElement("tr");
                const date = document.createElement("td");
                date.textContent = item.date.toGMTString();
                const password = document.createElement("td");
                password.textContent = item.password;
                password.addEventListener("click", (e) => {
                    navigator.clipboard.writeText(e.target.textContent).then(() => {
                        bootstrap.Toast.getOrCreateInstance($("#password-copied-toast")[0]).show();
                    });
                });
                tr.appendChild(date);
                tr.appendChild(password);
                table.append(tr);
            });
            modal.show();
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
            const tr = document.createElement("tr");
            let rows = [];
            for (let i = 0; i < 6; i++) {
                rows.push(document.createElement("td"));
            }
            rows[0].textContent = cred.getName();
            rows[1].textContent = cred.getURL();
            rows[2].textContent = cred.getUsername();
            rows[3].textContent = cred.getPassword();
            rows[4].textContent = cred.getCreatedAt().toGMTString();
            rows[5].textContent = cred.getLastModAt().toGMTString();
            rows.forEach(td => {
                tr.appendChild(td);
            });

            tr.addEventListener("click", () => {
                const modal = new bootstrap.Modal($("#view-cred-modal")[0]);
                $("#view-cred-name").text(cred.getName());
                $("#view-cred-url").text(cred.getURL());
                $("#view-cred-username").text(cred.getUsername());
                $("#view-cred-password").text(cred.getPassword());
                $("#view-cred-modal span").click((e) => {
                    navigator.clipboard.writeText(e.target.textContent);
                });
                modal.show();
            });

            const delButton = document.createElement("button");
            delButton.classList.add("btn", "btn-danger", "bi", "bi-trash3-fill", "mt-1", "ms-1");
            delButton.addEventListener("click", (e) => {
                this.#user.removeCredential(cred);
                this.buildCredsTable();
                this.saveDataLS();
                e.stopPropagation();
            });
            tr.appendChild(delButton);

            const editButton = document.createElement("button");
            editButton.classList.add("btn", "btn-info", "bi", "bi-pencil-square", "mt-1", "ms-1");
            editButton.addEventListener("click", (e) => {
                const modal = new bootstrap.Modal($("#edit-cred-modal")[0]);
                $("#edit-cred-name").val(cred.getName());
                $("#edit-cred-url").val(cred.getURL());
                $("#edit-cred-username").val(cred.getUsername());
                $("#edit-cred-password").val(cred.getPassword());
                $("#edit-cred-save").click(() => {
                    cred.setName($("#edit-cred-name").val());
                    cred.setURL($("#edit-cred-url").val());
                    cred.setUsername($("#edit-cred-username").val());
                    cred.setPassword($("#edit-cred-password").val());
                    this.buildCredsTable();
                    this.saveDataLS();
                    modal.hide();
                });
                e.stopPropagation();
                modal.show();
            });
            tr.appendChild(editButton);

            tableBody.append(tr);
        });
    }

    addCred(name, url, username, password) {
        this.#user.addCredential(new Credential(username, password, url, name));
        this.buildCredsTable();
        this.saveDataLS();
    }

    exportData() {
        const data = this.#user.toJSON();
        Crypt.encrypt(data, this.#user.getPasswordHash()).then(encrypted => {
            this.#fileHandler.writeToFile(encrypted);
        });
    }

    saveDataLS() {
        const data = this.#user.toJSON();
        Crypt.encrypt(data, this.#user.getPasswordHash()).then(encrypted => {
            localStorage.setItem("japm", JSON.stringify(encrypted));
        });
    }

    loadDataLS(username, password) {
        let data = localStorage.getItem("japm");
        if (data == null) {
            return;
        }
        return Crypt.decryptBlob(JSON.parse(data), password).then(data => {
            const user = new User(data.username, data.password_hash, null);
            user.setCredentials(data.credentials);
            user.setGeneratorHistory(data.generator_history);
            this.setUser(user);
            if (this.#user.getUsername() != username) {
                console.log("Invalid username");
                $("#login-error").removeClass("d-none");
                return;
            }
            this.updateState(JAPM.State.AUTHENTICATED);
        }).catch(() => {
            console.error("Invalid password");
            $("#login-error").removeClass("d-none");
        });
    }

}

$(document).ready(() => {
    document.japm = new JAPM();
});

window.addEventListener("beforeunload", (event) => {
    if (document.japm != undefined && document.japm.state == JAPM.State.AUTHENTICATED) {
        document.japm.saveDataLS();
    };
    event.preventDefault();
});