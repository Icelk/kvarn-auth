/**
 * @param username{string} the username
 * @param password{string} the password
 * @param authPage{string} the path where the authentication backend code is mounted to
 * @returns a promise which resolves to the response. You should check the status.
 */
export async function login(username, password, authPath = "/auth") {
    let te = new TextEncoder()
    // to get the UTF-8 string length
    let encodedUsername = te.encode(username)
    return await fetch(authPath, { method: "PUT", body: `${encodedUsername.length + 1}\n${username}\n${password}` })
}
/**
 * @param authPage{string} the path where the authentication backend code is mounted to
 * @returns a promise which resolves to the response. You should check the status.
 */
export async function logout(authPath = "/auth") {
    return await fetch(authPath, { method: "DELETE" })
}

/**
 * The option `with_relaxed_httponly` has to be enabled in the builder for the auth config in Kvarn.
 * Else, this will always return `null`.
 *
 * @param authPage {string} the path where the authentication backend code is mounted to
 * @returns {null | string | number | [string, number] | any} The status of the logged in user, or null if none.
 */
export function loginStatus(cookieName = "auth-jwt") {
    let cookies = document.cookie
    let index = cookies.indexOf(`${cookieName}=`)
    cookies = cookies.slice(index)
    let jwtCookie = cookies.split("; ")[0]
    let payload = jwtCookie.split(".")[1]
    let decoded = decodeURIComponent(escape(window.atob(payload)))
    let data = JSON.parse(decoded)
    let variant = data["__variant"]
    if (variant === undefined) {
        if (data.num !== undefined && data.text !== undefined) {
            return [data.text, data.num]
        }
        if (data.num !== undefined) {
            return data.num
        }
        if (data.text !== undefined) {
            return data.text
        }
    } else {
        if (variant === "t") {
            return data.text
        }
        if (variant === "n") {
            return data.num
        }
        if (variant === "tn") {
            return [data.text, data.num]
        }
        if (variant === "s") {
            if (data["__deserialize_v"] === true) {
                return data.v
            } else {
                delete data.iat
                delete data.exp
                delete data.__variant
                delete data.__deserialize_v
                return data
            }
        }
    }
    return null
}
