import type Fio from "../../src/fio"
import {getFio} from "../test_utils"

describe("runTestsDevice", async () => {
    let fio: Fio = {} as Fio

    beforeEach(async () => {
        fio = await getFio()
    })

    afterEach(async () => {
        await (fio as any).t.close()
    })

    it("Should run device tests", async () => {
        await fio.runTests()
    })
})
