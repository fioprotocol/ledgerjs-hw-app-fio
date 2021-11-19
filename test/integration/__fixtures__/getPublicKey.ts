export type TestCase = {
  path: string,
  expected: { publicKey: string}
}

export const testsPublicKey: TestCase[] = [
    {
        path: "44'/235'/0'/0/0",
        expected: {
            publicKey:
        "04a9a222bc3b1a5a58ada17d10069b3961ebd0f917d4b2106031a061915ca9cc24a06941e0a4c0d5e266850ff980ad349ab8b027c93bf4aead1984168ad43e30ab",
        },
    },
    {
        path: "44'/235'/0'/0/2000",
        expected: {
            publicKey:
        "0484e52dfea57b8f1787488a356374cd8e8515b8ad8db3dd4f9088d8e42ed2fb6d571e8894cccbdbf15e1bd84f8b4362f52d1b5b712b9775c0a51cdd5ee9a9e8ca",
        },
    },
]
