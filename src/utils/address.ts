import {InvalidDataReason} from "../errors"
import {HARDENED} from "../types/public"
import {isString, parseIntFromStr, validate} from "./parse"

function parseBIP32Index(str: string, errMsg: InvalidDataReason): number {
    let base = 0
    if (str.endsWith("'")) {
        str = str.slice(0, -1)
        base = HARDENED
    }
    const i = parseIntFromStr(str, errMsg)
    validate(i >= 0, errMsg)
    validate(i < HARDENED, errMsg)
    return base + i
}

export function str_to_path(data: string): Array<number> {
    const errMsg = InvalidDataReason.INVALID_PATH
    validate(isString(data), errMsg)
    validate(data.length > 0, errMsg)

    return data.split("/").map(function (x: string): number {
        return parseBIP32Index(x, errMsg)
    })
}