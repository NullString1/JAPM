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

    getCredenitals() {
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
}

class FileHandler {
    loadFromFile(file) {
    }

    writeToFile(data) {
    }
}

class Crypt {
    encrypt(data) {
    }

    decrypt(data) {
    }
}

class JAPM {
    #user;
    #fileHandler;
    #crypt;
    #state;

    static State = {
        UNAUTHENTICATED: "unauthenticated",
        AUTHENTICATED: "authenticated"
    };

    constructor() {
        this.#fileHandler = new FileHandler();
        this.#crypt = new Crypt();
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
                }
            });
        }
    }

    setupLogin(){
        $("#login-container").removeClass("d-none");
        $("#login-submit").click(() => {
            console.log("Login clicked");
            this.login($("#login-username").val(), $("#login-password").val());
        });
    }

    setupMainView() {
        $("#login-container").addClass("d-none");
        $("#add-cred-container").removeClass("d-none");
        $("#list-cred-container").removeClass("d-none");
    }

}

$(document).ready(function() {
    const user = new User("u", "p");
    const japm = new JAPM();
    japm.setUser(user);
});
