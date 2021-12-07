import type {Serial, Version} from "../types/public"
import { buf_to_hex } from "../utils/serialize"
import {INS} from "./common/ins"
import type {Interaction, SendParams} from "./common/types"
import {ensureLedgerAppVersionCompatible} from "./getVersion"

const send = (params: {
    p1: number,
    p2: number,
    data: Buffer,
    expectedResponseLength?: number
}): SendParams => ({ins: INS.GET_SERIAL, ...params})


export function* getSerial(version: Version): Interaction<Serial> {
    ensureLedgerAppVersionCompatible(version)

    const P1_UNUSED = 0x00
    const P2_UNUSED = 0x00
    const response = yield send({
        p1: P1_UNUSED,
        p2: P2_UNUSED,
        data: Buffer.alloc(0),
        expectedResponseLength: 7,
    })

    const serial = buf_to_hex(response)
    return {serial}
}
