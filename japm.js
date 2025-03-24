class User {
    #username;
    #password_hash;
    #credentials = [];
    #created_at;
    #generator_history = [];

    constructor(username, password_hash = null, password = null, credentials = [], generator_history = [], created_at = new Date()) {
        this.#username = username;
        if (password_hash == null && password != null) {
            this.setPassword(password);
        } else if (password_hash != null) {
            this.#password_hash = password_hash;
        } else {
            throw new Error("Either password hash or password must be provided.");
        }
        this.#created_at = created_at;
        this.#credentials = credentials;
        this.#generator_history = generator_history;
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
    #weak;

    constructor(username, password, url, name, created_at = new Date(), last_modified_at = new Date()) {
        this.#username = username;
        this.#password = password;
        this.#url = url;
        this.#name = name;
        this.#created_at = created_at;
        this.#last_modified_at = last_modified_at;
        this.#weak = this.isWeak();
    }

    isWeak() {
        if (this.#password.length < 8) {
            return true;
        }
        if (this.#password.match(/[A-Z]/) == null) {
            return true;
        }
        if (this.#password.match(/[a-z]/) == null) {
            return true;
        }
        if (this.#password.match(/[0-9]/) == null) {
            return true;
        }
        if (this.#password.match(/[!@#$%^&*()_\+\-=[\]{};':,.<>?]/) == null) {
            return true;
        }
        return false;
    }

    getWeak() {
        return this.#weak;
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
        this.#weak = this.isWeak();
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
                    return new Credential(cred.username, cred.password, cred.url, cred.name, new Date(cred.created_at), new Date(cred.last_modified_at));
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
    #autoLogoutTimer;

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
                $("#login-error").addClass("d-none");
                $("#main-container").addClass("d-none");
                if (localStorage.getItem("japm") != null) {
                    $("#reset-japm").removeClass("d-none");
                }
                clearTimeout(this.#autoLogoutTimer);
                break;
            case JAPM.State.AUTHENTICATED:
                window.history.pushState({}, "", "#/main"); // Change URL to /main 
                $("#login-container").addClass("d-none");
                $("#main-container").removeClass("d-none");
                this.buildCredsTable();
                this.autoLogout();
                break;
        }

    };

    login(username, password) {
        this.loadDataLS(username, password);
    }

    autoLogout() {
        setTimeout(() => {
            this.#user = undefined;
            this.updateState(JAPM.State.UNAUTHENTICATED);
            $("#login-username").val("");
            $("#login-password").val("");
        }, 5 * 60 * 1000);
    }

    setupLogin() {
        $("#login-submit").off("click").on("click", () => {
            const pass = $("#login-password").val();
            if ($("#login-submit").text() === "Register") {
                let valid = true;
                if (pass.length < 8) {
                    $("#password-weak-length").addClass("text-danger").removeClass("text-success");
                    valid = false;
                } else
                    $("#password-weak-length").addClass("text-success").removeClass("text-danger");

                if (pass.match(/[A-Z]/) == null) {
                    $("#password-weak-upper").addClass("text-danger").removeClass("text-success");
                    valid = false;
                } else
                    $("#password-weak-upper").addClass("text-success").removeClass("text-danger");

                if (pass.match(/[a-z]/) == null) {
                    $("#password-weak-lower").addClass("text-danger").removeClass("text-success");
                    valid = false;
                } else
                    $("#password-weak-lower").addClass("text-success").removeClass("text-danger");;

                if (pass.match(/[0-9]/) == null) {
                    $("#password-weak-num").addClass("text-danger").removeClass("text-success");
                    valid = false;
                } else
                    $("#password-weak-num").addClass("text-success").removeClass("text-danger");;

                if (pass.match(/[!@#$%^&*()_\+\-=[\]{};':,.<>?]/) == null) {
                    $("#password-weak-symb").addClass("text-danger").removeClass("text-success");
                    valid = false;
                } else
                    $("#password-weak-symb").addClass("text-success").removeClass("text-danger");;

                if (!valid) {
                    $("#password-weak").removeClass("d-none");
                    return;
                } else
                    $("#password-weak").addClass("d-none");
            }
            const username = $("#login-username").val();
            if (username === "") {
                $("#login-error").removeClass("d-none");
                return;
            }
            this.login(username, pass);
        });
        $("#load-button").off("click").on("click", () => {
            $("#load-input").trigger("click");
        });
        $("#load-input").change(() => {
            const li = $("#load-input")[0];
            const file = li.files[0];
            const reader = new FileReader();
            reader.onload = () => {
                const data = JSON.parse(reader.result);
                let d = JSON.parse(localStorage.getItem("japm")) || {};
                const username = Object.keys(data)[0];
                if (!d.hasOwnProperty(username)) {
                    d[username] = data[username];
                    localStorage.setItem("japm", JSON.stringify(d));
                    $("#data-loaded-toast").toast("show");
                } else {
                    console.log("Data for this user already exists.");
                    $("#user-exists-toast").toast("show");
                }
            };
            reader.readAsText(file);
        });
        $("#login-password").off("keypress").on("keypress", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                $("#login-submit").trigger("click");
            }
        });
        $("#login-username").off("keyup").on("keyup", (e) => {
            if (JSON.parse(localStorage.getItem("japm")).hasOwnProperty($("#login-username").val())) {
                $("#login-submit").text("Login");
            } else {
                $("#login-submit").text("Register");
            }
        });
        $("#reset-data-button").off("click").on("click", () => {
            localStorage.removeItem("japm");
            $("#login-submit").text("Register");
            $("#reset-japm").addClass("d-none");
            $("#login-error").addClass("d-none");
            $("#login-username").val("");
            $("#login-password").val("");
        });
        $(".input-group-text").off("click").on("click", (e) => {
            const input = e.target.parentNode.previousElementSibling;
            input.setAttribute("type", input.getAttribute("type") === "password" ? "text" : "password")
        })
        $("#dyslexic-toggle").off("click").on("click", () => {
            $("body").toggleClass("dyslexic");
        });
        if (localStorage.getItem("japm") != null) {
            $("#reset-japm").removeClass("d-none");
        }

    }

    setupMainView() {
        $("#add-cred-submit").off("click").on("click", () => {
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
        $("#password").off("keypress").on("keypress", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                $("#add-cred-submit").trigger("click");
            }
        });
        $("#save-button").off("click").on("click", () => {
            this.exportData();
        });
        $("#logout-button").off("click").on("click", () => {
            this.#user = undefined;
            this.updateState(JAPM.State.UNAUTHENTICATED);
            $("#login-username").val("");
            $("#login-password").val("");
        });
        $("#gen-pass-submit").off("click").on("click", () => {
            const length = parseInt($("#gen-pass-length").val());
            if (length < 5 || length > 70) {
                return;
            }
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
        $("#gen-pass-span").off("click").on("click", () => {
            navigator.clipboard.writeText($("#gen-pass-span").text()).then(() => {
                bootstrap.Toast.getOrCreateInstance($("#password-copied-toast")[0]).show();
            });
        });
        $("#gen-pass-history").off("click").on("click", () => {
            const modal = new bootstrap.Modal($("#gen-pass-history-modal")[0]);
            const table = $("#gen-pass-history-table tbody");
            table.empty();
            this.#user.getGeneratorHistory().forEach(item => {
                const tr = document.createElement("tr");
                const date = document.createElement("td");
                try {
                    date.textContent = item.date.toLocaleDateString("en-gb", {
                        weekday: "short",
                        year: '2-digit',
                        month: '2-digit',
                        day: '2-digit',
                        hour: "2-digit",
                        minute: "2-digit"
                    });
                } catch (e) {
                    date.textContent = new Date(item.date).toLocaleDateString("en-gb", {
                        weekday: "short",
                        year: '2-digit',
                        month: '2-digit',
                        day: '2-digit',
                        hour: "2-digit",
                        minute: "2-digit"
                    });
                }
                const password = document.createElement("td");
                password.classList.add("user-select-all");
                password.textContent = item.password;
                password.addEventListener("click", (e) => {
                    navigator.clipboard.writeText(e.target.textContent).then(() => {
                        bootstrap.Toast.getOrCreateInstance($("#password-copied-toast")[0]).show();
                    });
                });
                const delButton = document.createElement("button");
                delButton.classList.add("btn", "bi", "bi-trash3-fill", "m-1");
                delButton.addEventListener("click", (e) => {
                    this.#user.setGeneratorHistory(this.#user.getGeneratorHistory().filter(i => i !== item));
                    this.saveDataLS();
                });
                tr.appendChild(date);
                tr.appendChild(password);
                tr.appendChild(delButton);
                table.prepend(tr);
            });
            $("#clear-gen-pass-history").off("click").on("click", () => {
                this.#user.setGeneratorHistory([]);
                $("#gen-pass-history-table tbody").empty();
                this.saveDataLS();
            });
            modal.show();
        });
        $('[data-bs-toggle="tooltip"]').tooltip();
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
            rows[0].textContent = cred.getName().length > 20 ? cred.getName().substring(0, 20) + "..." : cred.getName();
            rows[1].textContent = cred.getURL().length > 20 ? cred.getURL().substring(0, 20) + "..." : cred.getURL();
            try {
                const url = new URL(cred.getURL().includes("://") ? cred.getURL() : "https://" + cred.getURL());
                const i = document.createElement("i");
                i.classList.add("bi", "bi-box-arrow-up-right", "ms-1");
                i.setAttribute("data-bs-toggle", "tooltip");
                i.setAttribute("title", "Open in new tab");
                i.style.cursor = "pointer";
                i.addEventListener("click", () => {
                    window.open(url.href, "_blank");
                });
                new bootstrap.Tooltip(i);
                rows[1].appendChild(i);
            } catch (e) {
                console.debug("Invalid URL");
            }
            rows[2].textContent = cred.getUsername().length > 20 ? cred.getUsername().substring(0, 20) + "..." : cred.getUsername();
            rows[3].textContent = "*".repeat(cred.getPassword().length > 15 ? 15 : cred.getPassword().length);
            if (cred.getWeak()) {
                const i = document.createElement("i");
                i.classList.add("bi", "bi-exclamation-triangle", "text-danger", "ms-1");
                i.setAttribute("data-bs-toggle", "tooltip");
                i.setAttribute("title", "Weak password");
                new bootstrap.Tooltip(i);
                rows[3].appendChild(i);
            }
            rows[4].textContent = cred.getCreatedAt().toLocaleDateString("en-gb", {
                weekday: "short",
                year: '2-digit',
                month: '2-digit',
                day: '2-digit',
                hour: "2-digit",
                minute: "2-digit"
            });
            rows[5].textContent = cred.getLastModAt().toLocaleDateString("en-gb", {
                weekday: "short",
                year: '2-digit',
                month: '2-digit',
                day: '2-digit',
                hour: "2-digit",
                minute: "2-digit"
            });
            rows.forEach(td => {
                tr.appendChild(td);
            });

            tr.addEventListener("click", () => {
                const modal = new bootstrap.Modal($("#view-cred-modal")[0]);
                $("#view-cred-name").text(cred.getName());
                $("#view-cred-url").text(cred.getURL());
                $("#view-cred-username").text(cred.getUsername());
                $("#view-cred-password").text(cred.getPassword());
                $("#view-cred-modal span").off("click").on("click", (e) => {
                    navigator.clipboard.writeText(e.target.textContent);
                });
                modal.show();
            });

            const delButton = document.createElement("button");
            delButton.classList.add("btn", "btn-danger", "bi", "bi-trash3-fill", "mt-1", "ms-1");
            delButton.setAttribute("aria-label", "Delete credential");
            delButton.addEventListener("click", (e) => {
                const modal = new bootstrap.Modal($("#delete-cred-modal")[0]);
                modal.show();
                $("#delete-cred-button").off("click").on("click", () => {
                    this.#user.removeCredential(cred);
                    this.buildCredsTable();
                    this.saveDataLS();
                    modal.hide();
                });
                e.stopPropagation();
            });
            tr.appendChild(delButton);

            const editButton = document.createElement("button");
            editButton.classList.add("btn", "btn-info", "bi", "bi-pencil-square", "mt-1", "ms-1");
            editButton.setAttribute("aria-label", "Edit credential");
            editButton.addEventListener("click", (e) => {
                const modal = new bootstrap.Modal($("#edit-cred-modal")[0]);
                $("#edit-cred-name").val(cred.getName());
                $("#edit-cred-url").val(cred.getURL());
                $("#edit-cred-username").val(cred.getUsername());
                $("#edit-cred-password").val(cred.getPassword());
                $("#edit-cred-save").off("click").on("click", () => {
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
            this.#fileHandler.writeToFile({[this.#user.getUsername()]: encrypted});
        });
    }

    saveDataLS() {
        const data = this.#user.toJSON();
        Crypt.encrypt(data, this.#user.getPasswordHash()).then(encrypted => {
            const existingData = JSON.parse(localStorage.getItem("japm")) || {};
            existingData[this.#user.getUsername()] = encrypted;
            localStorage.setItem("japm", JSON.stringify(existingData));
        });
    }

    loadDataLS(username, password) {
        let data = localStorage.getItem("japm") || "{}";
        data = JSON.parse(data);
        if (data.hasOwnProperty(username)) {
            Crypt.decryptBlob(data[username], password).then(decrypted => {
                const user = new User(decrypted.username, decrypted.password_hash, null, decrypted.credentials, decrypted.generator_history, decrypted.created_at);
                this.setUser(user);
                this.updateState(JAPM.State.AUTHENTICATED);
            }).catch(() => {
                console.error("Invalid password");
                $("#login-error").removeClass("d-none");
            }
            );
        } else {
            this.#user = new User(username, null, password);
            const sInterval = setInterval(() => {
                if (this.#user.getPasswordHash() != null) {
                    clearInterval(sInterval);
                    this.saveDataLS();
                }
            }, 100);
            this.updateState(JAPM.State.AUTHENTICATED);
        }
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