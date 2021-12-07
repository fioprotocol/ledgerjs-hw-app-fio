/**
 * Reason for throwing [[InvalidData]] error.
 * @category Errors
 */
export enum InvalidDataReason {
    GET_PUB_KEY_PATH_IS_NOT_ARRAY = "ext pub key path is not an array",
    INVALID_CHAIN_ID = "invalid chain id",
    INVALID_PATH = "invalid path",
    CONTEXT_FREE_ACTIONS_NOT_SUPPORTED = "context free actions not supported",
    MULTIPLE_ACTIONS_NOT_SUPPORTED = "multiple actions not supported",
    ACTION_NOT_SUPPORTED = "action not suported",
    INVALID_ACCOUNT = "invalid account",
    INVALID_NAME = "invalid name",
    INVALID_AMOUNT = "invalid amount",
    INVALID_MAX_FEE = "invalid max fee",
    INVALID_EXPIRATION = "invalid expiration",
    INVALID_REF_BLOCK_NUM = "invalid ref block num",
    INVALID_REF_BLOCK_PREFIX = "invalid ref block prefix",
    MULTIPLE_AUTHORIZATION_NOT_SUPPORTED = "multiple authorization not supported",
    INVALID_ACTION_AUTHORIZATION = "invalid action authorization",
    INVALID_PAYEE_PUBKEY = "invalid payee pubkey",
    INVALID_TPID = "invalid tpid",
    INVALID_ACTOR = "invalid actor",
    INVALID_PERMISSION = "invalid permission",
    ACTION_DATA_TOO_LONG = "action data too long",
}
