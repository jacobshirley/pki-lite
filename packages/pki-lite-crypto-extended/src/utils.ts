export const toForgeBytes = (arr: Uint8Array) => {
    let bytes = ''
    for (let i = 0; i < arr.length; i++) {
        bytes += String.fromCharCode(arr[i])
    }
    return bytes
}

export const fromForgeBytes = (str: string) => {
    const arr = new Uint8Array(str.length)
    for (let i = 0; i < str.length; i++) {
        arr[i] = str.charCodeAt(i)
    }
    return arr
}
