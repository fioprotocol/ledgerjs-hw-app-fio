import {ErrorBase} from "../errors"

export function assert(cond: boolean, errMsg: string): asserts cond {
    if (!cond) throw new ErrorBase('Assertion failed' + errMsg ? ': ' + errMsg : '')
}
