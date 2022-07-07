# Plugin API

`miradord` makes use of external plugins to define its re-vaulting policy 
(decide whether to broadcast a Cancel transaction for a given Unvault).

## Hooks

### `new_block`

Upon notifying a new block chain tip, if the state of vaults under watch changed, 
`miradord` will call into every plugin with information about the state updates. 
It will expect a response containing a list of vaults to re-vault (which may be empty).

#### Watchtower message

| Field                | Type                                             | Description                                                                           |
| -------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `method`             | string                                           | The method's name, here "`new_block`".                                                |
| `blockheight`        | integer                                          | Current block height                                                                  |
| `config`             | json object                                      | Plugin configuration. Empty if none was specified in `miradord`'s configuration file. |
| `block_info`         | [attempts overview resource](#attempts-overview) | An overview of the spending attempts at the current block                             |

##### Attempts overview 

An overview of the spending attempts at the current block.

| Field                 | Type                                       | Description                                                                                        |
| --------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `new_attempts`        | array of [Vault resource](#vault-resource) | Vaults that were just un-vaulted                                                                   |
| `successful_attempts` | array of string                            | Outpoints of vaults that were spent (defined as an Unvault being spent after the timelock expired) |
| `revaulted_attempts`  | array of string                            | Outpoints of the revaulted vaults                                                                  |

##### Vault resource 

| Field              | Type           | Description                                                                                             |
| ------------------ | -------------- | --------------------------------------------                                                            |
| `value`            | integer        | Value of the vault in satoshis                                                                          |
| `deposit_outpoint` | string         | Deposit outpoint of the vault                                                                           |
| `unvault_tx`       | string         | Psbt of the unvault transaction of the vault                                                            |
| `candidate_tx`     | string or null | Hex encoded transaction spending the vault, null if the watchtower did not retrieve it from coordinator |

#### Plugin Response

| Field     | Type            | Description                       |
| --------- | --------------- | --------------------------------- |
| `revault` | array of string | Outpoints of the vaults to cancel |
