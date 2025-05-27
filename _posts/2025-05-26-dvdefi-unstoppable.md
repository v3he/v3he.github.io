---
title: "Damn Vulnerable DeFi: Unstoppable — Halting a Vault with One Rogue Transfer"
date: 2025-05-25 12:00:00 +0200
categories: [Smart Contract Security, Damn Vulnerable DeFi]
tags: [web3, smart-contracts, solidity, ctfs, damn-vulnerable-defi]
media_subpath: /assets/img/smart-contracts/unstoppable/
description: "How I break a lending vault by sending a single rogue token transfer, throwing off its internal accounting and halting all future loans."
image:
  path: unstoppable.jpg
---

## Introduction

![Challenge Description](description.jpg)

> 🔗 Challenge: [Unstoppable @ DamnVulnerableDeFi](https://www.damnvulnerabledefi.xyz/challenges/unstoppable)  
> 📂 Source code: [v3he/damn-vulnerable-defi/test/unstoppable](https://github.com/v3he/damn-vulnerable-defi/tree/master/test/unstoppable)

## Understanding the Setup

Ok, so let’s look at what’s actually going on.

We’re given a tokenized vault that holds `1,000,000 DVT` tokens and offers **free flash loans** for a limited time during a “grace period.” Flash loans are short-term loans that must be borrowed and repaid within the same transaction — if you don’t pay it back, the transaction reverts entirely.

The core components involved in this challenge are:

### 🏦 [`UnstoppableVault.sol`](https://github.com/v3he/damn-vulnerable-defi/blob/master/src/unstoppable/UnstoppableVault.sol){:target="_blank"}

The vault is an ERC4626-compliant contract that:
- Accepts deposits and tracks internal balances via shares (`totalSupply`)
- Offers flash loans by calling `flashLoan()` with some accounting checks
- Requires internal accounting (`convertToShares(totalSupply)`) to match the actual token balance (`totalAssets()`)
- Pays fees *after* the grace period ends

### 🔍 [`UnstoppableMonitor.sol`](https://github.com/v3he/damn-vulnerable-defi/blob/master/src/unstoppable/UnstoppableMonitor.sol){:target="_blank"}

The monitor is a separate contract that:
- Calls `checkFlashLoan()` to test if a flash loan of `n DVT` tokens is still possible
- If the flash loan fails, it:
  - Emits an event (`FlashLoanStatus(false)`)
  - Pauses the vault
  - Transfers vault ownership back to the deployer

This acts like a safety net — a way for developers to detect if the flash loan feature is misbehaving before the vault goes fully permissionless.

## Solving Conditions

Let’s look at what the test uses to determine if the challenge is solved:

```js
function _isSolved() private {
    // Flashloan check must fail
    vm.prank(deployer);
    vm.expectEmit();
    emit UnstoppableMonitor.FlashLoanStatus(false);
    monitorContract.checkFlashLoan(100e18);

    // And now the monitor paused the vault and transferred ownership to deployer
    assertTrue(vault.paused(), "Vault is not paused");
    assertEq(vault.owner(), deployer, "Vault did not change owner");
}
```

To pass the challenge, we need two things to happen:

1. The monitor’s call to `checkFlashLoan()` must fail, meaning flash loans are no longer possible.
2. The monitor must pause the vault and transfer ownership back to the deployer.

So, the entire exploit comes down to causing the vault’s `flashLoan()` function to revert by corrupting its assumptions.

## Finding the Break

Let’s take a closer look at how this whole thing is monitored.

The monitor calls this function to check whether the vault can still issue a flash loan:

```js
function checkFlashLoan(uint256 amount) external onlyOwner {
    require(amount > 0);

    address asset = address(vault.asset());

    try vault.flashLoan(this, asset, amount, bytes("")) {
        emit FlashLoanStatus(true);
    } catch {
        // Something bad happened
        emit FlashLoanStatus(false);

        // Pause the vault
        vault.setPause(true);

        // Transfer ownership to allow review & fixes
        vault.transferOwnership(owner);
    }
}
```

As we can see, the way to trigger the success conditions is by making `flashLoan()` revert. That’s our only objective.

So now let’s look at the actual `flashLoan()` function inside the vault:

```js
function flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    if (amount == 0) revert InvalidAmount(0); // fail early
    if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
    uint256 balanceBefore = totalAssets();
    if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement

    // transfer tokens out + execute callback on receiver
    ERC20(_token).safeTransfer(address(receiver), amount);

    // callback must return magic value, otherwise assume it failed
    uint256 fee = flashFee(_token, amount);
    if (
        receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data)
            != keccak256("IERC3156FlashBorrower.onFlashLoan")
    ) {
        revert CallbackFailed();
    }

    // pull amount + fee from receiver, then pay the fee to the recipient
    ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
    ERC20(_token).safeTransfer(feeRecipient, fee);

    return true;
}
```

As we can see, the loan can fail for multiple reasons — the amount might be zero, the token might be unsupported, or the callback might return the wrong value.

But we don’t control the vault contract, and we can’t modify the monitor.  
We're just the player with 10 tokens — so our only power is how we interact with the vault.

The line that stands out is this one:

```js
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

This is a sanity check: the vault expects its own internal accounting (the result of `convertToShares(totalSupply)`) to match the actual token balance (`totalAssets()`).

So the question becomes: **Can we somehow desync those values from the outside?**

## Spoiler: Yes, We Can

But first, we need to understand **how the vault is doing the counting** — and where the mismatch comes from.

The vault relies on two separate things to track tokens:

- 🔸 `totalAssets()` — this reflects the **actual balance** of tokens held by the vault (via `token.balanceOf(address(this))`)
- 🔸 `totalSupply` — this is the **internal accounting**: how many shares the vault thinks are issued (only updated via `deposit()` or `mint()`)

Normally, these stay in sync because deposits go through the vault’s functions, which update both the actual balance and the internal `totalSupply`.

But here's the catch:  
Nothing stops us from calling `token.transfer(vault, amount)` directly. If we do that, the actual balance increases — but the vault has **no idea** it happened. `totalSupply` doesn’t change.

So if the vault later runs this check:

```js
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

…it compares an outdated `convertToShares()` value against the new balance — and the whole flash loan reverts.

## Executing the Exploit

At this point, the only thing left to do is trigger the imbalance ourselves — and we can do it with a single line of code.

Just a direct `transfer()` is enough to break the vault’s assumptions.

Here’s the entire code for the test case:

```js
function test_unstoppable() public checkSolvedByPlayer {
    token.transfer(address(vault), 1 ether); // desyncing in balance vs shares
}
```

That’s it.

We’re directly transferring `1 DVT` token to the vault from the player address, bypassing its `deposit()` function.

This increases the vault’s actual balance (`totalAssets()`), but its `totalSupply` remains unchanged — because `transfer()` doesn’t trigger any vault logic.

The next time the monitor calls `checkFlashLoan()`, the vault fails its own internal check:

```js
// convertToShares(totalSupply) == 1_000_000 ether
// balanceBefore == 1_000_001 ether
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
```

And just like that, the loan reverts → the monitor sees the failure → pauses the vault → transfers ownership → ✅ challenge solved.

## Conclusion

This was definitely one of the “baby” challenges — the exploit path is short, the interaction is minimal, and there are no complex contract deployments or clever tricks.

But despite that, it still took me time.  
Not because the solution is hard — but because I needed to understand what a flash loan actually is, how ERC4626 vaults manage internal accounting, and why `totalSupply` doesn't always match the actual token balance.

Hopefully in the next few challenges, I’ll spend less time getting unblocked by fundamentals and more time breaking things.

```js
total_hours_wasted_here = 1.5 // +1h reading docs, exploring the vault, and realizing "oh... that's it?"
```

As promised and water clear: I literally spent an hour to write a one-line exploit 😅