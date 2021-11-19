import type {Version} from "../types/public"
import {INS} from "./common/ins"
import type {Interaction} from "./common/types"

export function* runTests(_version: Version): Interaction<void> {
    yield {
        ins: INS.RUN_TESTS,
        p1: 0x00,
        p2: 0x00,
        data: Buffer.alloc(0),
        expectedResponseLength: 0,
    }
}