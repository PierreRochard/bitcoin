// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    LogPrintf("GetNextWorkRequired: %d %d %d\n", pindexLast->nHeight, pindexLast->GetBlockTime(), pindexLast->nBits);

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
    LogPrintf("GetNextWorkRequired: nProofOfWorkLimit %d\n", nProofOfWorkLimit);

    // Only change once per difficulty adjustment interval
    LogPrintf("GetNextWorkRequired: DifficultyAdjustmentInterval %d\n", params.DifficultyAdjustmentInterval());
    LogPrintf("GetNextWorkRequired: nHeight %d\n", pindexLast->nHeight);
    LogPrintf("GetNextWorkRequired: nHeight+1 %d\n", pindexLast->nHeight+1);
    LogPrintf("GetNextWorkRequired: nHeight+1 %% DifficultyAdjustmentInterval %d\n", (pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval());
    LogPrintf("GetNextWorkRequired: Is it time to adjust difficulty? %d\n", (pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0);
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        LogPrintf("GetNextWorkRequired: Not time to adjust difficulty\n");
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        LogPrintf("GetNextWorkRequired: Not time to adjust difficulty and not special difficulty rule returning nBits %d\n", pindexLast->nBits);
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    LogPrintf("GetNextWorkRequired: nHeightFirst %d\n", nHeightFirst);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    LogPrintf("GetNextWorkRequired: pindexFirst->GetBlockTime() %d\n", pindexFirst->GetBlockTime());
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    LogPrintf("CalculateNextWorkRequired: params.fPowNoRetargeting %d\n", params.fPowNoRetargeting);
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    LogPrintf("CalculateNextWorkRequired: nActualTimespan %d\n", nActualTimespan);
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
        LogPrintf("Limit adjustment step: nActualTimespan %d\n", nActualTimespan);
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;
        LogPrintf("Limit adjustment step: nActualTimespan %d\n", nActualTimespan);

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    LogPrintf("CalculateNextWorkRequired: bnPowLimit %s\n", bnPowLimit.ToString());
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }
    LogPrintf("CalculateNextWorkRequired: bnNew %s\n", bnNew.ToString());

    bnNew *= nActualTimespan;
    LogPrintf("CalculateNextWorkRequired: bnNew %s\n", bnNew.ToString());
    bnNew /= params.nPowTargetTimespan;
    LogPrintf("CalculateNextWorkRequired: bnNew %s\n", bnNew.ToString());

    LogPrintf("CalculateNextWorkRequired: bnNew > bnPowLimit %d\n", bnNew > bnPowLimit);
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
        LogPrintf("CalculateNextWorkRequired: bnNew %s\n", bnNew.ToString());

    LogPrintf("CalculateNextWorkRequired: bnNew.GetCompact() %d\n", bnNew.GetCompact());
    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {

        LogPrintf("PermittedDifficultyTransition: height %d\n", height);
        LogPrintf("PermittedDifficultyTransition: DifficultyAdjustmentInterval %d\n", params.DifficultyAdjustmentInterval());
        LogPrintf("PermittedDifficultyTransition: height %% DifficultyAdjustmentInterval %d\n", height % params.DifficultyAdjustmentInterval());
        LogPrintf("PermittedDifficultyTransition: height %d is a difficulty adjustment interval\n", height);
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;
        LogPrintf("PermittedDifficultyTransition: smallest_timespan %d\n", smallest_timespan);
        LogPrintf("PermittedDifficultyTransition: largest_timespan %d\n", largest_timespan);

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        LogPrintf("PermittedDifficultyTransition: pow_limit %s\n", pow_limit.ToString());
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);
        LogPrintf("PermittedDifficultyTransition: observed_new_target %s\n", observed_new_target.ToString());

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        LogPrintf("PermittedDifficultyTransition: largest_difficulty_target %s\n", largest_difficulty_target.ToString());
        largest_difficulty_target *= largest_timespan;
        LogPrintf("PermittedDifficultyTransition: largest_difficulty_target %s\n", largest_difficulty_target.ToString());
        largest_difficulty_target /= params.nPowTargetTimespan;
        LogPrintf("PermittedDifficultyTransition: largest_difficulty_target %s\n", largest_difficulty_target.ToString());

        LogPrintf("PermittedDifficultyTransition: largest_difficulty_target > pow_limit %d\n", largest_difficulty_target > pow_limit);
        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        LogPrintf("PermittedDifficultyTransition: maximum_new_target %s\n", maximum_new_target.ToString());
        LogPrintf("PermittedDifficultyTransition: maximum_new_target < observed_new_target %d\n", maximum_new_target < observed_new_target);
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        LogPrintf("PermittedDifficultyTransition: smallest_difficulty_target %s\n", smallest_difficulty_target.ToString());
        smallest_difficulty_target *= smallest_timespan;
        LogPrintf("PermittedDifficultyTransition: smallest_difficulty_target %s\n", smallest_difficulty_target.ToString());
        smallest_difficulty_target /= params.nPowTargetTimespan;
        LogPrintf("PermittedDifficultyTransition: smallest_difficulty_target %s\n", smallest_difficulty_target.ToString());

        LogPrintf("PermittedDifficultyTransition: smallest_difficulty_target > pow_limit %d\n", smallest_difficulty_target > pow_limit);
        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        LogPrintf("PermittedDifficultyTransition: minimum_new_target %s\n", minimum_new_target.ToString());
        LogPrintf("PermittedDifficultyTransition: minimum_new_target > observed_new_target %d\n", minimum_new_target > observed_new_target);
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most signficant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return (hash.data()[31] & 0x80) == 0;
#else
    return CheckProofOfWorkImpl(hash, nBits, params);
#endif
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
