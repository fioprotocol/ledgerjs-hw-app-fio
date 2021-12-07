import {DeviceVersionUnsupported} from "../errors"
import type {DeviceCompatibility, Version} from "../types/public"
import {INS} from "./common/ins"
import type {Interaction, SendParams} from "./common/types"

const send = (params: {
    p1: number,
    p2: number,
    data: Buffer,
    expectedResponseLength?: number
}): SendParams => ({ins: INS.GET_VERSION, ...params})


export function* getVersion(): Interaction<Version> {
    // moving getVersion() logic to private function in order
    // to disable concurrent execution protection done by this.transport.decorateAppAPIMethods()
    // when invoked from within other calls to check app version

    const P1_UNUSED = 0x00
    const P2_UNUSED = 0x00
    const response = yield send({
        p1: P1_UNUSED,
        p2: P2_UNUSED,
        data: Buffer.alloc(0),
        expectedResponseLength: 4,
    })
    const [major, minor, patch, flags_value] = response

    const FLAG_IS_DEBUG = 1
    
    const flags = {
        isDebug: (flags_value & FLAG_IS_DEBUG) === FLAG_IS_DEBUG,
    }
    return {major, minor, patch, flags}
}

export function getCompatibility(version: Version): DeviceCompatibility {
    // We restrict forward compatibility only to backward-compatible semver changes
    const v0_0 = isLedgerAppVersionAtLeast(version, 0, 0) &&
                 isLedgerAppVersionAtMost(version, 0, Infinity)

    return {
        isCompatible: v0_0,
        recommendedVersion: v0_0 ? null : '0.0',
    }
}

export function isLedgerAppVersionAtLeast(
    version: Version,
    minMajor: number,
    minMinor: number
): boolean {
    const {major, minor} = version

    return major > minMajor || (major === minMajor && minor >= minMinor)
}

export function isLedgerAppVersionAtMost(
    version: Version,
    maxMajor: number,
    maxMinor: number
): boolean {
    const {major, minor} = version

    return major < maxMajor || (major === maxMajor && minor <= maxMinor)
}

export function ensureLedgerAppVersionCompatible(
    version: Version,
): void {
    const {isCompatible, recommendedVersion} = getCompatibility(version)

    if (!isCompatible) {
        throw new DeviceVersionUnsupported(`Device app version unsupported. Please upgrade to ${recommendedVersion}.`)
    }
}

