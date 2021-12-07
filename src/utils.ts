import {InvalidDataReason} from "./errors"
import {HARDENED} from "./types/public"
import {assert} from "./utils/assert"
import {isArray, isBuffer, isInteger, isString, parseIntFromStr, validate} from "./utils/parse"
import {buf_to_hex, buf_to_uint16, hex_to_buf, path_to_buf, uint32_to_buf} from './utils/serialize'

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

const sum = (arr: Array<number>) => arr.reduce((x, y) => x + y, 0)

export function chunkBy(data: Buffer, chunkLengths: Array<number>) {
    assert(isBuffer(data), "invalid buffer")
    assert(isArray(chunkLengths), "invalid chunks")
    for (const len of chunkLengths) {
        assert(isInteger(len), "bad chunk length")
        assert(len > 0, "bad chunk length")
    }
    assert(data.length <= sum(chunkLengths), "data too short")

    let offset = 0
    const result = []

    const restLength = data.length - sum(chunkLengths)

    for (let c of [...chunkLengths, restLength]) {
        result.push(data.slice(offset, offset + c))

        offset += c
    }

    return result
}

export function stripRetcodeFromResponse(response: Buffer): Buffer {
    assert(isBuffer(response), "invalid buffer")
    assert(response.length >= 2, "response too short")

    const L = response.length - 2
    const retcode = buf_to_uint16(response.slice(L, L + 2))
    assert(retcode === 0x9000, `Invalid retcode ${retcode}`)
    return response.slice(0, L)
}

export default {
    // reexporting for tests
    // FIXME: following is workaround for cyclic import runtime resolve issues
    hex_to_buf: (data: any) => hex_to_buf(data),
    buf_to_hex: (data: any) => buf_to_hex(data),
    path_to_buf: (data: any) => path_to_buf(data),
    uint32_to_buf: (data: any) => uint32_to_buf(data),

    assert,

    str_to_path,

    chunkBy,
    stripRetcodeFromResponse,
}
