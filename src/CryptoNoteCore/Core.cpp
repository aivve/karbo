// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2017, The Monero Project
// Copyright (c) 2018, The Galaxia Project Developers
// Copyright (c) 2018, The TurtleCoin Developers
// Copyright (c) 2017-2019, The The Karbo Developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

#include <algorithm>
#include <numeric>
#include <set>
#include <unordered_set>

#include "Core.h"
#include "Common/ShuffleGenerator.h"
#include "Common/Math.h"
#include "Common/MemoryInputStream.h"
#include "CryptoNoteTools.h"
#include "CryptoNoteFormatUtils.h"
#include "BlockchainCache.h"
#include "BlockchainStorage.h"
#include "BlockchainUtils.h"
#include "CryptoNoteCore/ITimeProvider.h"
#include "CryptoNoteCore/CoreErrors.h"
#include "CryptoNoteCore/MemoryBlockchainStorage.h"
#include "CryptoNoteCore/TransactionExtra.h"
#include "CryptoNoteCore/TransactionPool.h"
#include "CryptoNoteCore/TransactionPoolCleaner.h"
#include "CryptoNoteCore/UpgradeManager.h"
#include "CryptoNoteProtocol/CryptoNoteProtocolHandlerCommon.h"

#include <System/Timer.h>
#include <boost/range/adaptor/reversed.hpp>

#include "TransactionApi.h"

using namespace Crypto;

namespace CryptoNote {

namespace {

template <class T>
std::vector<T> preallocateVector(size_t elements) {
  std::vector<T> vect;
  vect.reserve(elements);
  return vect;
}
UseGenesis addGenesisBlock = UseGenesis(true);

class TransactionSpentInputsChecker {
public:
  bool haveSpentInputs(const Transaction& transaction) {
    for (const auto& input : transaction.inputs) {
      if (input.type() == typeid(KeyInput)) {
        auto inserted = alreadSpentKeyImages.insert(boost::get<KeyInput>(input).keyImage);
        if (!inserted.second) {
          return true;
        }
      } else if (input.type() == typeid(MultisignatureInput)) {
        const auto& multisignature = boost::get<MultisignatureInput>(input);
        auto inserted =
            alreadySpentMultisignatures.insert(std::make_pair(multisignature.amount, multisignature.outputIndex));
        if (!inserted.second) {
          return true;
        }
      }
    }

    return false;
  }

private:
  std::unordered_set<Crypto::KeyImage> alreadSpentKeyImages;
  std::set<std::pair<uint64_t, uint64_t>> alreadySpentMultisignatures;
};

inline IBlockchainCache* findIndexInChain(IBlockchainCache* blockSegment, const Crypto::Hash& blockHash) {
  assert(blockSegment != nullptr);
  while (blockSegment != nullptr) {
    if (blockSegment->hasBlock(blockHash)) {
      return blockSegment;
    }

    blockSegment = blockSegment->getParent();
  }

  return nullptr;
}

inline IBlockchainCache* findIndexInChain(IBlockchainCache* blockSegment, uint32_t blockIndex) {
  assert(blockSegment != nullptr);
  while (blockSegment != nullptr) {
    if (blockIndex >= blockSegment->getStartBlockIndex() &&
        blockIndex < blockSegment->getStartBlockIndex() + blockSegment->getBlockCount()) {
      return blockSegment;
    }

    blockSegment = blockSegment->getParent();
  }

  return nullptr;
}

size_t getMaximumTransactionAllowedSize(size_t blockSizeMedian, const Currency& currency) {
  //assert(blockSizeMedian * 2 > currency.minerTxBlobReservedSize());

  //return blockSizeMedian * 2 - currency.minerTxBlobReservedSize();
  return currency.maxTransactionSizeLimit();
}

BlockTemplate extractBlockTemplate(const RawBlock& block) {
  BlockTemplate blockTemplate;
  if (!fromBinaryArray(blockTemplate, block.block)) {
    throw std::system_error(make_error_code(error::AddBlockErrorCode::DESERIALIZATION_FAILED));
  }

  return blockTemplate;
}

Crypto::Hash getBlockHash(const RawBlock& block) {
  BlockTemplate blockTemplate = extractBlockTemplate(block);
  return CachedBlock(blockTemplate).getBlockHash();
}

TransactionValidatorState extractSpentOutputs(const CachedTransaction& transaction) {
  TransactionValidatorState spentOutputs;
  const auto& cryptonoteTransaction = transaction.getTransaction();

  for (const auto& input : cryptonoteTransaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      const KeyInput& in = boost::get<KeyInput>(input);
      bool r = spentOutputs.spentKeyImages.insert(in.keyImage).second;
      if (r) {}
      assert(r);
    } else if (input.type() == typeid(MultisignatureInput)) {
      const MultisignatureInput& in = boost::get<MultisignatureInput>(input);
      bool r = spentOutputs.spentMultisignatureGlobalIndexes.insert(std::make_pair(in.amount, in.outputIndex)).second;
      assert(r);
    } else {
      assert(false);
    }
  }

  return spentOutputs;
}

TransactionValidatorState extractSpentOutputs(const std::vector<CachedTransaction>& transactions) {
  TransactionValidatorState resultOutputs;
  for (const auto& transaction: transactions) {
    auto transactionOutputs = extractSpentOutputs(transaction);
    mergeStates(resultOutputs, transactionOutputs);
  }

  return resultOutputs;
}

int64_t getEmissionChange(const Currency& currency, IBlockchainCache& segment, uint32_t previousBlockIndex,
                          const CachedBlock& cachedBlock, uint64_t cumulativeSize, uint64_t cumulativeFee) {

  uint64_t reward = 0;
  int64_t emissionChange = 0;
  auto alreadyGeneratedCoins = segment.getAlreadyGeneratedCoins(previousBlockIndex);
  auto lastBlocksSizes = segment.getLastBlocksSizes(currency.rewardBlocksWindow(), previousBlockIndex, addGenesisBlock);
  auto blocksSizeMedian = Common::medianValue(lastBlocksSizes);
  if (!currency.getBlockReward(cachedBlock.getBlock().majorVersion, blocksSizeMedian,
                               cumulativeSize, alreadyGeneratedCoins, cumulativeFee, reward, emissionChange)) {
    throw std::system_error(make_error_code(error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG));
  }

  return emissionChange;
}

uint32_t findCommonRoot(IMainChainStorage& storage, IBlockchainCache& rootSegment) {
  assert(storage.getBlockCount());
  assert(rootSegment.getBlockCount());
  assert(rootSegment.getStartBlockIndex() == 0);
  assert(getBlockHash(storage.getBlockByIndex(0)) == rootSegment.getBlockHash(0));

  uint32_t left = 0;
  uint32_t right = std::min(storage.getBlockCount() - 1, rootSegment.getBlockCount() - 1);
  while (left != right) {
    assert(right >= left);
    uint32_t checkElement = left + (right - left) / 2 + 1;
    if (getBlockHash(storage.getBlockByIndex(checkElement)) == rootSegment.getBlockHash(checkElement)) {
      left = checkElement;
    } else {
      right = checkElement - 1;
    }
  }

  return left;
}

const std::chrono::seconds OUTDATED_TRANSACTION_POLLING_INTERVAL = std::chrono::seconds(60);

}

Core::Core(const Currency& currency, Logging::ILogger& logger, Checkpoints&& checkpoints, System::Dispatcher& dispatcher,
           std::unique_ptr<IBlockchainCacheFactory>&& blockchainCacheFactory, std::unique_ptr<IMainChainStorage>&& mainchainStorage)
    : currency(currency), dispatcher(dispatcher), contextGroup(dispatcher), logger(logger, "Core"), checkpoints(std::move(checkpoints)),
      upgradeManager(new UpgradeManager()), blockchainCacheFactory(std::move(blockchainCacheFactory)),
      mainChainStorage(std::move(mainchainStorage)), initialized(false) {

  upgradeManager->addMajorBlockVersion(BLOCK_MAJOR_VERSION_2, currency.upgradeHeight(BLOCK_MAJOR_VERSION_2));
  upgradeManager->addMajorBlockVersion(BLOCK_MAJOR_VERSION_3, currency.upgradeHeight(BLOCK_MAJOR_VERSION_3));
  upgradeManager->addMajorBlockVersion(BLOCK_MAJOR_VERSION_4, currency.upgradeHeight(BLOCK_MAJOR_VERSION_4));
  upgradeManager->addMajorBlockVersion(BLOCK_MAJOR_VERSION_5, currency.upgradeHeight(BLOCK_MAJOR_VERSION_5));

  transactionPool = std::unique_ptr<ITransactionPoolCleanWrapper>(new TransactionPoolCleanWrapper(
    std::unique_ptr<ITransactionPool>(new TransactionPool(logger)),
    std::unique_ptr<ITimeProvider>(new RealTimeProvider()),
    logger,
    currency.mempoolTxLiveTime()));
}

Core::~Core() {
  contextGroup.interrupt();
  contextGroup.wait();
}

bool Core::addMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return queueList.insert(messageQueue);
}

bool Core::removeMessageQueue(MessageQueue<BlockchainMessage>& messageQueue) {
  return queueList.remove(messageQueue);
}

bool Core::notifyObservers(BlockchainMessage&& msg) /* noexcept */ {
  try {
    for (auto& queue : queueList) {
      queue.push(std::move(msg));
    }
    return true;
  } catch (std::exception& e) {
    logger(Logging::WARNING) << "failed to notify observers: " << e.what();
    return false;
  }
}

uint32_t Core::getTopBlockIndex() const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  throwIfNotInitialized();

  return chainsLeaves[0]->getTopBlockIndex();
}

Crypto::Hash Core::getTopBlockHash() const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());

  throwIfNotInitialized();

  return chainsLeaves[0]->getTopBlockHash();
}

Crypto::Hash Core::getBlockHashByIndex(uint32_t blockIndex) const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  assert(blockIndex <= getTopBlockIndex());

  throwIfNotInitialized();

  return chainsLeaves[0]->getBlockHash(blockIndex);
}

uint64_t Core::getBlockTimestampByIndex(uint32_t blockIndex) const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  assert(blockIndex <= getTopBlockIndex());

  throwIfNotInitialized();

  auto timestamps = chainsLeaves[0]->getLastTimestamps(1, blockIndex, addGenesisBlock);
  assert(!(timestamps.size() == 1));

  return timestamps[0];
}

bool Core::hasBlock(const Crypto::Hash& blockHash) const {
  throwIfNotInitialized();
  return findSegmentContainingBlock(blockHash) != nullptr;
}

BlockTemplate Core::getBlockByIndex(uint32_t index) const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  assert(index <= getTopBlockIndex());

  throwIfNotInitialized();
  IBlockchainCache* segment = findMainChainSegmentContainingBlock(index);
  assert(segment != nullptr);

  return restoreBlockTemplate(segment, index);
}

BlockTemplate Core::getBlockByHash(const Crypto::Hash& blockHash) const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());

  throwIfNotInitialized();
  IBlockchainCache* segment = findMainChainSegmentContainingBlock(blockHash);
  if (segment == nullptr) {
    segment = findAlternativeSegmentContainingBlock(blockHash);
    if (segment == nullptr) {
      throw std::runtime_error("Requested hash wasn't found");
    }
  }

  uint32_t blockIndex = segment->getBlockIndex(blockHash);

  return restoreBlockTemplate(segment, blockIndex);
}

std::vector<Crypto::Hash> Core::buildSparseChain() const {
  throwIfNotInitialized();
  Crypto::Hash topBlockHash = chainsLeaves[0]->getTopBlockHash();
  return doBuildSparseChain(topBlockHash);
}

std::vector<RawBlock> Core::getBlocks(uint32_t minIndex, uint32_t count) const {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());

  throwIfNotInitialized();

  std::vector<RawBlock> blocks;
  if (count > 0) {
    auto cache = chainsLeaves[0];
    auto maxIndex = std::min(minIndex + count - 1, cache->getTopBlockIndex());
    blocks.reserve(count);
    while (cache) {
      if (cache->getTopBlockIndex() >= maxIndex) {
        auto minChainIndex = std::max(minIndex, cache->getStartBlockIndex());
        for (; minChainIndex <= maxIndex; --maxIndex) {
          blocks.emplace_back(cache->getBlockByIndex(maxIndex));
          if (maxIndex == 0) {
            break;
          }
        }
      }

      if (blocks.size() == count) {
        break;
      }

      cache = cache->getParent();
    }
  }
  std::reverse(blocks.begin(), blocks.end());

  return blocks;
}

void Core::getBlocks(const std::vector<Crypto::Hash>& blockHashes, std::vector<RawBlock>& blocks,
                     std::vector<Crypto::Hash>& missedHashes) const {
  throwIfNotInitialized();

  for (const auto& hash : blockHashes) {
    IBlockchainCache* blockchainSegment = findSegmentContainingBlock(hash);
    if (blockchainSegment == nullptr) {
      missedHashes.push_back(hash);
    } else {
      uint32_t blockIndex = blockchainSegment->getBlockIndex(hash);
      assert(blockIndex <= blockchainSegment->getTopBlockIndex());

      blocks.push_back(blockchainSegment->getBlockByIndex(blockIndex));
    }
  }
}

void Core::copyTransactionsToPool(IBlockchainCache* alt) {
  assert(alt != nullptr);
  while (alt != nullptr) {
    if (mainChainSet.count(alt) != 0)
      break;
    auto transactions = alt->getRawTransactions(alt->getTransactionHashes());
    for (auto& transaction : transactions) {
      if (addTransactionToPool(std::move(transaction))) {
        // TODO: send notification
      }
    }
    alt = alt->getParent();
  }
}

bool Core::queryBlocks(const std::vector<Crypto::Hash>& blockHashes, uint64_t timestamp, uint32_t& startIndex,
                       uint32_t& currentIndex, uint32_t& fullOffset, std::vector<BlockFullInfo>& entries) const {
  assert(entries.empty());
  assert(!chainsLeaves.empty());
  assert(!chainsStorage.empty());
  throwIfNotInitialized();

  try {
    IBlockchainCache* mainChain = chainsLeaves[0];
    currentIndex = mainChain->getTopBlockIndex();

    startIndex = findBlockchainSupplement(blockHashes); // throws

    fullOffset = mainChain->getTimestampLowerBoundBlockIndex(timestamp);
    if (fullOffset < startIndex) {
      fullOffset = startIndex;
    }

    size_t hashesPushed = pushBlockHashes(startIndex, fullOffset, BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT, entries);

    if (startIndex + hashesPushed != fullOffset) {
      return true;
    }

    fillQueryBlockFullInfo(fullOffset, currentIndex, BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, entries);

    return true;
  } catch (std::exception& e) {
    logger(Logging::ERROR) << "Failed to query blocks: " << e.what();
    return false;
  }
}

bool Core::queryBlocksLite(const std::vector<Crypto::Hash>& knownBlockHashes, uint64_t timestamp, uint32_t& startIndex,
                           uint32_t& currentIndex, uint32_t& fullOffset, std::vector<BlockShortInfo>& entries) const {
  assert(entries.empty());
  assert(!chainsLeaves.empty());
  assert(!chainsStorage.empty());

  throwIfNotInitialized();
  try {
    IBlockchainCache* mainChain = chainsLeaves[0];
    currentIndex = mainChain->getTopBlockIndex();

    startIndex = findBlockchainSupplement(knownBlockHashes); // throws

    // Stops bug where wallets fail to sync, because timestamps have been adjusted after syncronisation.
    // check for a query of the blocks where the block index is non-zero, but the timestamp is zero
    // indicating that the originator did not know the internal time of the block, but knew which block
    // was wanted by index.  Fullfill this by getting the time of m_blocks[startIndex].timestamp.

    if (startIndex > 0 && timestamp == 0) {
      if (startIndex <= mainChain->getTopBlockIndex()) {
        RawBlock block = mainChain->getBlockByIndex(startIndex);
        auto blockTemplate = extractBlockTemplate(block);
        timestamp = blockTemplate.timestamp;
      }
    }

    fullOffset = mainChain->getTimestampLowerBoundBlockIndex(timestamp);
    if (fullOffset < startIndex) {
      fullOffset = startIndex;
    }

    size_t hashesPushed = pushBlockHashes(startIndex, fullOffset, BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT, entries);

    if (startIndex + static_cast<uint32_t>(hashesPushed) != fullOffset) {
      return true;
    }

    fillQueryBlockShortInfo(fullOffset, currentIndex, BLOCKS_SYNCHRONIZING_DEFAULT_COUNT, entries);

    return true;
  } catch (std::exception& e) {
	logger(Logging::ERROR) << "Failed to query blocks: " << e.what();
    return false;
  }
}

void Core::getTransactions(const std::vector<Crypto::Hash>& transactionHashes, std::vector<BinaryArray>& transactions,
                           std::vector<Crypto::Hash>& missedHashes) const {
  assert(!chainsLeaves.empty());
  assert(!chainsStorage.empty());
  throwIfNotInitialized();

  IBlockchainCache* segment = chainsLeaves[0];
  assert(segment != nullptr);

  std::vector<Crypto::Hash> leftTransactions = transactionHashes;

  // find in main chain
  do {
    std::vector<Crypto::Hash> missedTransactions;
    segment->getRawTransactions(leftTransactions, transactions, missedTransactions);

    leftTransactions = std::move(missedTransactions);
    segment = segment->getParent();
  } while (segment != nullptr && !leftTransactions.empty());

  if (leftTransactions.empty()) {
    return;
  }

  // find in alternative chains
  for (size_t chain = 1; chain < chainsLeaves.size(); ++chain) {
    segment = chainsLeaves[chain];

    while (mainChainSet.count(segment) == 0 && !leftTransactions.empty()) {
      std::vector<Crypto::Hash> missedTransactions;
      segment->getRawTransactions(leftTransactions, transactions, missedTransactions);

      leftTransactions = std::move(missedTransactions);
      segment = segment->getParent();
    }
  }

  missedHashes.insert(missedHashes.end(), leftTransactions.begin(), leftTransactions.end());
}

Difficulty Core::getBlockDifficulty(uint32_t blockIndex) const {
  throwIfNotInitialized();
  IBlockchainCache* mainChain = chainsLeaves[0];
  auto difficulties = mainChain->getLastCumulativeDifficulties(2, blockIndex, addGenesisBlock);
  if (difficulties.size() == 2) {
    return difficulties[1] - difficulties[0];
  }

  assert(difficulties.size() == 1);
  return difficulties[0];
}

Difficulty Core::getDifficultyForNextBlock() const {
  throwIfNotInitialized();
  IBlockchainCache* mainChain = chainsLeaves[0];

  return mainChain->getDifficultyForNextBlock();
}

std::vector<Crypto::Hash> Core::findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds,
                                                         size_t maxCount, uint32_t& totalBlockCount,
                                                         uint32_t& startBlockIndex) const {
  assert(!remoteBlockIds.empty());
  assert(remoteBlockIds.back() == getBlockHashByIndex(0));
  throwIfNotInitialized();

  totalBlockCount = getTopBlockIndex() + 1;
  startBlockIndex = findBlockchainSupplement(remoteBlockIds);

  return getBlockHashes(startBlockIndex, static_cast<uint32_t>(maxCount));
}

bool Core::checkProofOfWork(Crypto::cn_context& context, const CachedBlock& block, Difficulty currentDifficulty) {
  if (block.getBlock().majorVersion < CryptoNote::BLOCK_MAJOR_VERSION_5) {
    return currency.checkProofOfWork(context, block, currentDifficulty);
  }

  Crypto::Hash proofOfWork;

  if (!getBlockLongHash(context, block, proofOfWork)) {
    return false;
  }

  if (!check_hash(proofOfWork, currentDifficulty)) {
    return false;
  }

  return true;
}

bool Core::getBlockLongHash(Crypto::cn_context &context, const CachedBlock& b, Crypto::Hash& res) {
  if (b.getBlock().majorVersion < CryptoNote::BLOCK_MAJOR_VERSION_5) {
    res = b.getBlockLongHash(context);
    return true;
  }

  BinaryArray pot, blockBinaryArray = b.getBlockHashingBinaryArray();

  // Phase 1

  Crypto::Hash hash_1, hash_2;

  // Hashing the current blockdata (preprocessing it)
  cn_fast_hash(blockBinaryArray.data(), blockBinaryArray.size(), hash_1);

  // Phase 2

  // throw our block into common pot
  pot.insert(std::end(pot), std::begin(blockBinaryArray), std::end(blockBinaryArray));

  // Get the corresponding 8 blocks from blockchain based on preparatory hash_1
  // and throw them into the pot too
  auto cache = findSegmentContainingBlock(b.getBlock().previousBlockHash);
  uint32_t maxHeight = std::min<uint32_t>(get_current_blockchain_height(), b.getBlockIndex() - 1 - currency.minedMoneyUnlockWindow_v1());

  for (uint8_t i = 1; i <= 8; i++) {
    uint8_t chunk[4] = {
      hash_1.data[i * 4 - 4],
      hash_1.data[i * 4 - 3],
      hash_1.data[i * 4 - 2],
      hash_1.data[i * 4 - 1]
    };

    uint32_t n = (chunk[0] << 24) |
      (chunk[1] << 16) |
      (chunk[2] << 8) |
      (chunk[3]);

    uint32_t height_i = n % maxHeight;
    RawBlock rawBlock = cache->getBlockByIndex(height_i);
    BlockTemplate blockTemplate = extractBlockTemplate(rawBlock);
    BinaryArray ba = CachedBlock(blockTemplate).getBlockHashingBinaryArray();

    pot.insert(std::end(pot), std::begin(ba), std::end(ba));
  }

  // Phase 3

  // stir the pot - hashing the 1 + 8 blocks as one continuous data, salt is hash_1
  Crypto::balloon_hash(pot.data(), hash_2, pot.size(), hash_1.data, sizeof(hash_1));

  res = hash_2;

  return true;
}

// Calculate ln(p) of Poisson distribution
// Original idea : https://stackoverflow.com/questions/30156803/implementing-poisson-distribution-in-c
// Using logarithms avoids dealing with very large (k!) and very small (p < 10^-44) numbers
// lam     - lambda parameter - in our case, how many blocks, on average, you would expect to see in the interval
// k       - k parameter - in our case, how many blocks we have actually seen
//           !!! k must not be zero
// return  - ln(p)

double calc_poisson_ln(double lam, uint64_t k)
{
  double logx = -lam + k * log(lam);
  do
  {
    logx -= log(k); // This can be tabulated
  } while(--k > 0);
    return logx;
}

std::error_code Core::addBlock(const CachedBlock& cachedBlock, RawBlock&& rawBlock) {
  throwIfNotInitialized();
  uint32_t blockIndex = cachedBlock.getBlockIndex();
  Crypto::Hash blockHash = cachedBlock.getBlockHash();
  std::ostringstream os;
  os << blockIndex << " (" << blockHash << ")";
  std::string blockStr = os.str();

  logger(Logging::DEBUGGING) << "Request to add block came for block " << blockStr;

  if (hasBlock(cachedBlock.getBlockHash())) {
    logger(Logging::DEBUGGING) << "Block " << blockStr << " already exists";
    return error::AddBlockErrorCode::ALREADY_EXISTS;
  }

  const auto& blockTemplate = cachedBlock.getBlock();
  const auto& previousBlockHash = blockTemplate.previousBlockHash;

  assert(rawBlock.transactions.size() == blockTemplate.transactionHashes.size());

  auto cache = findSegmentContainingBlock(previousBlockHash);
  if (cache == nullptr) {
    logger(Logging::WARNING) << "Block " << blockStr << " rejected as orphaned";
    return error::AddBlockErrorCode::REJECTED_AS_ORPHANED;
  }

  std::vector<CachedTransaction> transactions;
  uint64_t cumulativeSize = 0;
  if (!extractTransactions(rawBlock.transactions, transactions, cumulativeSize)) {
    logger(Logging::WARNING) << "Couldn't deserialize raw block transactions in block " << blockStr;
    return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
  }

  auto coinbaseTransactionSize = getObjectBinarySize(blockTemplate.baseTransaction);
  assert(coinbaseTransactionSize < std::numeric_limits<decltype(coinbaseTransactionSize)>::max());
  auto cumulativeBlockSize = coinbaseTransactionSize + cumulativeSize;
  TransactionValidatorState validatorState;

  auto previousBlockIndex = cache->getBlockIndex(previousBlockHash);
  auto mainChainCache = chainsLeaves[0];

  auto currentBlockchainHeight = mainChainCache->getTopBlockIndex();
  if (!checkpoints.isAlternativeBlockAllowed(currentBlockchainHeight, previousBlockIndex + 1)) {
    logger(Logging::DEBUGGING) << "Block " << cachedBlock.getBlockHash() << std::endl <<
    " can't be accepted for alternative chain: block height " << previousBlockIndex + 1 << std::endl <<
    " is too deep below blockchain height " << currentBlockchainHeight;
    return error::AddBlockErrorCode::REJECTED_AS_ORPHANED;
  }

  bool addOnTop = cache->getTopBlockIndex() == previousBlockIndex;
  auto maxBlockCumulativeSize = currency.maxBlockCumulativeSize(previousBlockIndex + 1);
  if (cumulativeBlockSize > maxBlockCumulativeSize) {
    logger(Logging::WARNING) << "Block " << blockStr << " has too big cumulative size";
    return error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG;
  }

  uint64_t minerReward = 0;
  auto blockValidationResult = validateBlock(cachedBlock, cache, minerReward);
  if (blockValidationResult) {
    logger(Logging::WARNING) << "Failed to validate block " << blockStr << ": " << blockValidationResult.message();
    return blockValidationResult;
  }

  auto currentDifficulty = cache->getDifficultyForNextBlock(previousBlockIndex);
  if (currentDifficulty == 0) {
    logger(Logging::DEBUGGING) << "Block " << blockStr << " has difficulty overhead";
    return error::BlockValidationError::DIFFICULTY_OVERHEAD;
  }

  uint64_t cumulativeFee = 0;

  for (const auto& transaction : transactions) {
    uint64_t fee = 0;
    auto transactionValidationResult = validateTransaction(transaction, validatorState, cache, fee, previousBlockIndex);
    if (transactionValidationResult) {
      logger(Logging::DEBUGGING) << "Failed to validate transaction " << transaction.getTransactionHash() << ": " << transactionValidationResult.message();
      return transactionValidationResult;
    }

    cumulativeFee += fee;
  }

  uint64_t reward = 0;
  int64_t emissionChange = 0;
  auto alreadyGeneratedCoins = cache->getAlreadyGeneratedCoins(previousBlockIndex);
  auto lastBlocksSizes = cache->getLastBlocksSizes(currency.rewardBlocksWindow(), previousBlockIndex, addGenesisBlock);
  auto blocksSizeMedian = Common::medianValue(lastBlocksSizes);

  if (!currency.getBlockReward(cachedBlock.getBlock().majorVersion, blocksSizeMedian,
                               cumulativeBlockSize, alreadyGeneratedCoins, cumulativeFee, reward, emissionChange)) {
    logger(Logging::WARNING) << "Block " << cachedBlock.getBlockHash() << " has too big cumulative size";
    return error::BlockValidationError::CUMULATIVE_BLOCK_SIZE_TOO_BIG;
  }

  if (minerReward != reward) {
    logger(Logging::WARNING) << "Block reward mismatch for block " << cachedBlock.getBlockHash()
                             << ". Expected reward: " << reward << ", got reward: " << minerReward;
    return error::BlockValidationError::BLOCK_REWARD_MISMATCH;
  }

  if (checkpoints.isInCheckpointZone(cachedBlock.getBlockIndex())) {
    if (!checkpoints.checkBlock(cachedBlock.getBlockIndex(), cachedBlock.getBlockHash())) {
      logger(Logging::WARNING) << "Checkpoint block hash mismatch for block " << cachedBlock.getBlockHash();
      return error::BlockValidationError::CHECKPOINT_BLOCK_HASH_MISMATCH;
    }
  } else if (!currency.checkProofOfWork(cryptoContext, cachedBlock, currentDifficulty)) {
    logger(Logging::WARNING) << "Proof of work too weak for block " << cachedBlock.getBlockHash();
    return error::BlockValidationError::PROOF_OF_WORK_TOO_WEAK;
  }

  auto ret = error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE;

  if (addOnTop) {
    if (cache->getChildCount() == 0) {
      // add block on top of leaf segment.
      auto hashes = preallocateVector<Crypto::Hash>(transactions.size());

      // TODO: exception safety
      if (cache == chainsLeaves[0]) {
        mainChainStorage->pushBlock(rawBlock);

        cache->pushBlock(cachedBlock, transactions, validatorState, cumulativeBlockSize, emissionChange, currentDifficulty, std::move(rawBlock));
		
        //actualizePoolTransactions();
        updateBlockMedianSize();
        actualizePoolTransactionsLite(validatorState);

        ret = error::AddBlockErrorCode::ADDED_TO_MAIN;
        logger(Logging::DEBUGGING) << "Block " << cachedBlock.getBlockHash() << " added to main chain. Index: " << (previousBlockIndex + 1);
        if ((previousBlockIndex + 1) % 100 == 0) {
          logger(Logging::INFO) << "Block " << cachedBlock.getBlockHash() << " added to main chain. Index: " << (previousBlockIndex + 1);
        }

        notifyObservers(makeDelTransactionMessage(std::move(hashes), Messages::DeleteTransaction::Reason::InBlock));
      } else {
        bool allowReorg = true;
        
        cache->pushBlock(cachedBlock, transactions, validatorState, cumulativeBlockSize, emissionChange, currentDifficulty, std::move(rawBlock));
        logger(Logging::WARNING) << "Block " << cachedBlock.getBlockHash() << " added to alternative chain. Index: " << (previousBlockIndex + 1);

        if (cache->getCurrentCumulativeDifficulty() > mainChainCache->getCurrentCumulativeDifficulty()) {
          int64_t reorgSize = cache->getTopBlockIndex() - cache->getStartBlockIndex() + 1;

          // Transactions comparison check
          // https://medium.com/@karbo.org/prevent-transaction-cancellation-in-51-attack-79ba03d191f0
          // Compare transactions in proposed alt chain vs current main chain
          // and reject if some transaction is missing in the alt chain
          logger(Logging::WARNING) << "Transactions comparison check triggered by reorg size " << reorgSize;
          std::vector<Crypto::Hash> mainChainTxHashes = mainChainCache->getTransactionHashes(cache->getStartBlockIndex(), cache->getTopBlockIndex());
          for (const auto& mainChainTxHash : mainChainTxHashes) {
            if (!cache->hasTransaction(mainChainTxHash)) {
              logger(Logging::ERROR) << "Attempting to switch to an alternate chain, but it lacks transaction "
                                     << Common::podToHex(mainChainTxHash)
                                     << " from main chain, rejected";
              allowReorg = false;
            }
          }
          mainChainTxHashes.clear();
          mainChainTxHashes.shrink_to_fit();

          // Poisson check, courtesy of Ryo Project and fireice_uk for this version
          // https://github.com/ryo-currency/ryo-writeups/blob/master/poisson-writeup.md
          // For longer reorgs, check if the timestamps are probable - if they aren't the diff algo has failed
          // This check is meant to detect an offline bypass of timestamp < time() + ftl check
          // It doesn't need to be very strict as it synergises with the median check
          if(reorgSize >= CryptoNote::parameters::POISSON_CHECK_TRIGGER)
          {
            std::vector<uint64_t> alt_chain = cache->getLastTimestamps(reorgSize);
            std::vector<uint64_t> main_chain = mainChainCache->getLastTimestamps(CryptoNote::parameters::POISSON_CHECK_DEPTH, cache->getStartBlockIndex() - 1, UseGenesis{false});

            logger(Logging::WARNING) << "Poisson check triggered by reorg size " << reorgSize;
            for(size_t i=0; i < alt_chain.size(); i++)
              logger(Logging::WARNING) << "DEBUG: alt_chain [" << i << "] " << alt_chain[i];
            for(size_t i=0; i < main_chain.size(); i++)
              logger(Logging::WARNING) << "DEBUG: main_chain [" << i << "] " << main_chain[i];

            uint64_t high_timestamp = alt_chain.back();
              std::reverse(main_chain.begin(), main_chain.end());

            uint64_t failed_checks = 0, i = 0;
            for(; i < CryptoNote::parameters::POISSON_CHECK_DEPTH; i++)
            {
              uint64_t low_timestamp = main_chain[i];

              if(low_timestamp >= high_timestamp)
              {
                logger(Logging::WARNING) << "Skipping check at depth " << i << " due to tampered timestamp on main chain.";
                failed_checks++;
                continue;
              }

              double lam = double(high_timestamp - low_timestamp) / double(CryptoNote::parameters::DIFFICULTY_TARGET);
              if(calc_poisson_ln(lam, reorgSize + i + 1) < CryptoNote::parameters::POISSON_LOG_P_REJECT)
              {
                logger(Logging::WARNING) << "Poisson check at depth " << i << " failed! delta_t: " << (high_timestamp - low_timestamp) << " size: " << reorgSize + i + 1;
                failed_checks++;
              }
              else
                logger(Logging::WARNING) << "Poisson check at depth " << i << " passed! delta_t: " << (high_timestamp - low_timestamp) << " size: " << reorgSize + i + 1;
            }

            logger(Logging::WARNING) << "Poisson check result " << failed_checks << " fails out of " << i;

            if(failed_checks > i / 2)
            {
              logger(Logging::WARNING) << "Attempting to move to an alternate chain, but it failed Poisson check! " << failed_checks << " fails out of " << i << " alt_chain_size: " << reorgSize;
               allowReorg = false;
            }
          }

          if(allowReorg)
          {
            size_t endpointIndex =
              std::distance(chainsLeaves.begin(), std::find(chainsLeaves.begin(), chainsLeaves.end(), cache));
            assert(endpointIndex != chainsStorage.size());
            assert(endpointIndex != 0);

            std::swap(chainsLeaves[0], chainsLeaves[endpointIndex]);
            updateMainChainSet();

            updateBlockMedianSize();
            actualizePoolTransactions();
            copyTransactionsToPool(chainsLeaves[endpointIndex]);

            switchMainChainStorage(chainsLeaves[0]->getStartBlockIndex(), *chainsLeaves[0]);

            ret = error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED;

            logger(Logging::WARNING) << "Switching to alternative chain! New top block hash: " << cachedBlock.getBlockHash() << ", index: " << (previousBlockIndex + 1)
              << ", previous top block hash: " << chainsLeaves[endpointIndex]->getTopBlockHash() << ", index: " << chainsLeaves[endpointIndex]->getTopBlockIndex();
          }
        }
      }
    } else {
      //add block on top of segment which is not leaf! the case when we got more than one alternative block on the same height
      auto newCache = blockchainCacheFactory->createBlockchainCache(currency, cache, previousBlockIndex + 1);
      cache->addChild(newCache.get());

      auto newlyForkedChainPtr = newCache.get();
      chainsStorage.emplace_back(std::move(newCache));
      chainsLeaves.push_back(newlyForkedChainPtr);

      logger(Logging::DEBUGGING) << "Adding alternative block: " << cachedBlock.getBlockHash();

      newlyForkedChainPtr->pushBlock(cachedBlock, transactions, validatorState, cumulativeBlockSize, emissionChange,
                                     currentDifficulty, std::move(rawBlock));

      updateMainChainSet();
      updateBlockMedianSize();
    }
  } else {
    logger(Logging::DEBUGGING) << "Adding alternative block: " << cachedBlock.getBlockHash();

    auto upperSegment = cache->split(previousBlockIndex + 1);
    //[cache] is lower segment now

    assert(upperSegment->getBlockCount() > 0);
    assert(cache->getBlockCount() > 0);

    if (upperSegment->getChildCount() == 0) {
      //newly created segment is leaf node
      //[cache] used to be a leaf node. we have to replace it with upperSegment
      auto found = std::find(chainsLeaves.begin(), chainsLeaves.end(), cache);
      assert(found != chainsLeaves.end());

      *found = upperSegment.get();
    }

    chainsStorage.emplace_back(std::move(upperSegment));

    auto newCache = blockchainCacheFactory->createBlockchainCache(currency, cache, previousBlockIndex + 1);
    cache->addChild(newCache.get());

    auto newlyForkedChainPtr = newCache.get();
    chainsStorage.emplace_back(std::move(newCache));
    chainsLeaves.push_back(newlyForkedChainPtr);

    newlyForkedChainPtr->pushBlock(cachedBlock, transactions, validatorState, cumulativeBlockSize, emissionChange,
      currentDifficulty, std::move(rawBlock));

    updateMainChainSet();
  }

  logger(Logging::DEBUGGING) << "Block: " << cachedBlock.getBlockHash() << " successfully added";
  notifyOnSuccess(ret, previousBlockIndex, cachedBlock, *cache);

  return ret;
}

void Core::actualizePoolTransactions() {
  auto& pool = *transactionPool;
  auto hashes = pool.getTransactionHashes();

  for (auto& hash : hashes) {
    auto tx = pool.getTransaction(hash);
    pool.removeTransaction(hash);

    if (!addTransactionToPool(std::move(tx))) {
      notifyObservers(makeDelTransactionMessage({hash}, Messages::DeleteTransaction::Reason::NotActual));
    }
  }
}

void Core::actualizePoolTransactionsLite(const TransactionValidatorState& validatorState) {
  auto& pool = *transactionPool;
  auto hashes = pool.getTransactionHashes();

  for (auto& hash : hashes) {
    auto tx = pool.getTransaction(hash);

    auto txState = extractSpentOutputs(tx);

    if (hasIntersections(validatorState, txState) || tx.getTransactionBinaryArray().size() > getMaximumTransactionAllowedSize(blockMedianSize, currency)) {
      pool.removeTransaction(hash);
      notifyObservers(makeDelTransactionMessage({ hash }, Messages::DeleteTransaction::Reason::NotActual));
    }
  }
}

void Core::switchMainChainStorage(uint32_t splitBlockIndex, IBlockchainCache& newChain) {
  assert(mainChainStorage->getBlockCount() > splitBlockIndex);

  auto blocksToPop = mainChainStorage->getBlockCount() - splitBlockIndex;
  for (size_t i = 0; i < blocksToPop; ++i) {
    mainChainStorage->popBlock();
  }

  for (uint32_t index = splitBlockIndex; index <= newChain.getTopBlockIndex(); ++index) {
    mainChainStorage->pushBlock(newChain.getBlockByIndex(index));
  }
}

void Core::notifyOnSuccess(error::AddBlockErrorCode opResult, uint32_t previousBlockIndex,
                           const CachedBlock& cachedBlock, const IBlockchainCache& cache) {
  switch (opResult) {
    case error::AddBlockErrorCode::ADDED_TO_MAIN:
      notifyObservers(makeNewBlockMessage(previousBlockIndex + 1, cachedBlock.getBlockHash()));
      break;
    case error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE:
      notifyObservers(makeNewAlternativeBlockMessage(previousBlockIndex + 1, cachedBlock.getBlockHash()));
      break;
    case error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED: {
      auto parent = cache.getParent();
      auto hashes = cache.getBlockHashes(cache.getStartBlockIndex(), cache.getBlockCount());
      hashes.insert(hashes.begin(), parent->getTopBlockHash());
      notifyObservers(makeChainSwitchMessage(parent->getTopBlockIndex(), std::move(hashes)));
      break;
    }
    default:
      assert(false);
      break;
  }
}

bool Core::handleBlockFound(BlockTemplate& b) {
  auto add_result = submitBlock(toBinaryArray(b));
  if (add_result != error::AddBlockErrorCode::ADDED_TO_MAIN &&
      add_result != error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE && 
      add_result != error::AddBlockErrorCode::ADDED_TO_ALTERNATIVE_AND_SWITCHED) {
    return false;
  }
  return true;
}

std::error_code Core::addBlock(RawBlock&& rawBlock) {
  throwIfNotInitialized();

  BlockTemplate blockTemplate;
  bool result = fromBinaryArray(blockTemplate, rawBlock.block);
  if (!result) {
    return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
  }

  CachedBlock cachedBlock(blockTemplate);
  return addBlock(cachedBlock, std::move(rawBlock));
}

std::error_code Core::submitBlock(BinaryArray&& rawBlockTemplate) {
  throwIfNotInitialized();

  BlockTemplate blockTemplate;
  bool result = fromBinaryArray(blockTemplate, rawBlockTemplate);
  if (!result) {
    logger(Logging::WARNING) << "Couldn't deserialize block template";
    return error::AddBlockErrorCode::DESERIALIZATION_FAILED;
  }

  RawBlock rawBlock;
  rawBlock.block = std::move(rawBlockTemplate);

  rawBlock.transactions.reserve(blockTemplate.transactionHashes.size());
  for (const auto& transactionHash : blockTemplate.transactionHashes) {
    if (!transactionPool->checkIfTransactionPresent(transactionHash)) {
      logger(Logging::WARNING) << "The transaction " << Common::podToHex(transactionHash)
                               << " is absent in transaction pool";
      return error::BlockValidationError::TRANSACTION_ABSENT_IN_POOL;
    }

    rawBlock.transactions.emplace_back(transactionPool->getTransaction(transactionHash).getTransactionBinaryArray());
  }

  CachedBlock cachedBlock(blockTemplate);
  return addBlock(cachedBlock, std::move(rawBlock));
}

bool Core::getTransactionGlobalIndexes(const Crypto::Hash& transactionHash,
                                       std::vector<uint32_t>& globalIndexes) const {
  throwIfNotInitialized();
  IBlockchainCache* segment = chainsLeaves[0];

  bool found = false;
  while (segment != nullptr && found == false) {
    found = segment->getTransactionGlobalIndexes(transactionHash, globalIndexes);
    segment = segment->getParent();
  }

  if (found) {
    return true;
  }

  for (size_t i = 1; i < chainsLeaves.size() && found == false; ++i) {
    segment = chainsLeaves[i];
    while (found == false && mainChainSet.count(segment) == 0) {
      found = segment->getTransactionGlobalIndexes(transactionHash, globalIndexes);
      segment = segment->getParent();
    }
  }

  return found;
}

bool Core::getRandomOutputs(uint64_t amount, uint16_t count, std::vector<uint32_t>& globalIndexes,
                            std::vector<Crypto::PublicKey>& publicKeys) const {
  throwIfNotInitialized();

  if (count == 0) {
    return true;
  }

  auto upperBlockLimit = getTopBlockIndex() - currency.minedMoneyUnlockWindow();
  if (upperBlockLimit < currency.minedMoneyUnlockWindow()) {
    logger(Logging::DEBUGGING) << "Blockchain height is less than mined unlock window";
    return false;
  }

  globalIndexes = chainsLeaves[0]->getRandomOutsByAmount(amount, count, getTopBlockIndex());
  if (globalIndexes.empty()) {
    return false;
  }

  std::sort(globalIndexes.begin(), globalIndexes.end());

  switch (chainsLeaves[0]->extractKeyOutputKeys(amount, getTopBlockIndex(), {globalIndexes.data(), globalIndexes.size()},
                                                publicKeys)) {
    case ExtractOutputKeysResult::SUCCESS:
      return true;
    case ExtractOutputKeysResult::INVALID_GLOBAL_INDEX:
      logger(Logging::DEBUGGING) << "Invalid global index is given";
      return false;
    case ExtractOutputKeysResult::OUTPUT_LOCKED:
      logger(Logging::DEBUGGING) << "Output is locked";
      return false;
  }

  return false;
}

bool Core::addTransactionToPool(const BinaryArray& transactionBinaryArray) {
  throwIfNotInitialized();

  Transaction transaction;
  if (!fromBinaryArray<Transaction>(transaction, transactionBinaryArray)) {
    logger(Logging::WARNING) << "Couldn't add transaction to pool due to deserialization error";
    return false;
  }

  CachedTransaction cachedTransaction(std::move(transaction));
  auto transactionHash = cachedTransaction.getTransactionHash();

  if (!addTransactionToPool(std::move(cachedTransaction))) {
    return false;
  }

  notifyObservers(makeAddTransactionMessage({transactionHash}));
  return true;
}

bool Core::addTransactionToPool(CachedTransaction&& cachedTransaction) {
  TransactionValidatorState validatorState;

  if (!isTransactionValidForPool(cachedTransaction, validatorState)) {
    return false;
  }

  auto transactionHash = cachedTransaction.getTransactionHash();
  if (!transactionPool->pushTransaction(std::move(cachedTransaction), std::move(validatorState))) {
    logger(Logging::DEBUGGING) << "Failed to push transaction " << transactionHash << " to pool, already exists";
    return false;
  }

  logger(Logging::DEBUGGING) << "Transaction " << transactionHash << " has been added to pool";
  return true;
}

bool Core::isTransactionValidForPool(const CachedTransaction& cachedTransaction, TransactionValidatorState& validatorState) {
  uint64_t fee;

  if (auto validationResult = validateTransaction(cachedTransaction, validatorState, chainsLeaves[0], fee, getTopBlockIndex())) {
    logger(Logging::DEBUGGING) << "Transaction " << cachedTransaction.getTransactionHash()
      << " is not valid. Reason: " << validationResult.message();
    return false;
  }

  auto maxTransactionSize = getMaximumTransactionAllowedSize(blockMedianSize, currency);

  if (cachedTransaction.getTransactionBinaryArray().size() > maxTransactionSize) {
    logger(Logging::WARNING) << "Transaction " << cachedTransaction.getTransactionHash()
      << " is not valid. Reason: transaction is too big (" << cachedTransaction.getTransactionBinaryArray().size()
      << "). Maximum allowed size is " << maxTransactionSize;
    return false;
  }

  bool isFusion = fee == 0 && currency.isFusionTransaction(cachedTransaction.getTransaction(), cachedTransaction.getTransactionBinaryArray().size(), getTopBlockIndex());
  if (!isFusion && (getTopBlockIndex() < CryptoNote::parameters::UPGRADE_HEIGHT_V4 ? (fee < currency.minimumFee()) :
    (fee < (getMinimalFee() - (getMinimalFee() * 20 / 100))))) {
    logger(Logging::WARNING) << "Transaction " << cachedTransaction.getTransactionHash()
      << " is not valid. Reason: fee is too small and it's not a fusion transaction";
    return false;
  }

  return true;
}

boost::optional<std::pair<MultisignatureOutput, uint64_t>> Core::getMultisignatureOutput(uint64_t amount,
                                                                                         uint32_t globalIndex) const {
  throwIfNotInitialized();

  MultisignatureOutput output;
  uint64_t unlockTime;
  if (chainsLeaves[0]->getMultisignatureOutputIfExists(amount, globalIndex, output, unlockTime)) {
    return {{output, unlockTime}};
  }
  return {};
}

std::vector<Crypto::Hash> Core::getPoolTransactionHashes() const {
  throwIfNotInitialized();

  return transactionPool->getTransactionHashes();
}

bool Core::getPoolChanges(const Crypto::Hash& lastBlockHash, const std::vector<Crypto::Hash>& knownHashes,
                          std::vector<BinaryArray>& addedTransactions,
                          std::vector<Crypto::Hash>& deletedTransactions) const {
  throwIfNotInitialized();

  std::vector<Crypto::Hash> newTransactions;
  getTransactionPoolDifference(knownHashes, newTransactions, deletedTransactions);

  addedTransactions.reserve(newTransactions.size());
  for (const auto& hash : newTransactions) {
    addedTransactions.emplace_back(transactionPool->getTransaction(hash).getTransactionBinaryArray());
  }

  return getTopBlockHash() == lastBlockHash;
}

bool Core::getPoolChangesLite(const Crypto::Hash& lastBlockHash, const std::vector<Crypto::Hash>& knownHashes,
                              std::vector<TransactionPrefixInfo>& addedTransactions,
                              std::vector<Crypto::Hash>& deletedTransactions) const {
  throwIfNotInitialized();

  std::vector<Crypto::Hash> newTransactions;
  getTransactionPoolDifference(knownHashes, newTransactions, deletedTransactions);

  addedTransactions.reserve(newTransactions.size());
  for (const auto& hash : newTransactions) {
    TransactionPrefixInfo transactionPrefixInfo;
    transactionPrefixInfo.txHash = hash;
    transactionPrefixInfo.txPrefix =
        static_cast<const TransactionPrefix&>(transactionPool->getTransaction(hash).getTransaction());
    addedTransactions.emplace_back(std::move(transactionPrefixInfo));
  }

  return getTopBlockHash() == lastBlockHash;
}

bool Core::getBlockTemplate(BlockTemplate& b, const AccountPublicAddress& adr, const BinaryArray& extraNonce,
                            Difficulty& difficulty, uint32_t& height) const {
  throwIfNotInitialized();

  height = getTopBlockIndex() + 1;
  difficulty = getDifficultyForNextBlock();
  if (difficulty == 0) {
    logger(Logging::ERROR, Logging::BRIGHT_RED) << "difficulty overhead.";
    return false;
  }

  b = boost::value_initialized<BlockTemplate>();
  b.majorVersion = getBlockMajorVersionForHeight(height);

  if (b.majorVersion == BLOCK_MAJOR_VERSION_1) {
    b.minorVersion = currency.upgradeHeight(BLOCK_MAJOR_VERSION_2) == IUpgradeDetector::UNDEF_HEIGHT ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
  } else if (b.majorVersion == BLOCK_MAJOR_VERSION_2 || b.majorVersion == BLOCK_MAJOR_VERSION_3) {
    if (currency.upgradeHeight(BLOCK_MAJOR_VERSION_3) == IUpgradeDetector::UNDEF_HEIGHT) {
      b.minorVersion = b.majorVersion == BLOCK_MAJOR_VERSION_2 ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
    } else {
      b.minorVersion = BLOCK_MINOR_VERSION_0;
    }

    b.parentBlock.majorVersion = BLOCK_MAJOR_VERSION_1;
    b.parentBlock.majorVersion = BLOCK_MINOR_VERSION_0;
    b.parentBlock.transactionCount = 1;

    TransactionExtraMergeMiningTag mmTag = boost::value_initialized<decltype(mmTag)>();
    if (!appendMergeMiningTagToExtra(b.parentBlock.baseTransaction.extra, mmTag)) {
      logger(Logging::ERROR, Logging::BRIGHT_RED)
          << "Failed to append merge mining tag to extra of the parent block miner transaction";
      return false;
    }
  } else if (b.majorVersion == BLOCK_MAJOR_VERSION_4) {
    b.minorVersion = currency.upgradeHeight(BLOCK_MAJOR_VERSION_4) == IUpgradeDetector::UNDEF_HEIGHT ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
  } else if (b.majorVersion >= BLOCK_MAJOR_VERSION_5) {
    b.minorVersion = currency.upgradeHeight(BLOCK_MAJOR_VERSION_5) == IUpgradeDetector::UNDEF_HEIGHT ? BLOCK_MINOR_VERSION_1 : BLOCK_MINOR_VERSION_0;
  }

  b.previousBlockHash = getTopBlockHash();
  b.timestamp = static_cast<uint64_t>(time(nullptr));

  // Don't generate a block template with invalid timestamp
  // Fix by Jagerman
  if(height >= currency.timestampCheckWindow(b.majorVersion)) {
    std::vector<uint64_t> timestamps;
    for(uint32_t offset = height - static_cast<uint32_t>(currency.timestampCheckWindow(b.majorVersion)); offset < height; ++offset){
      timestamps.push_back(getBlockTimestampByIndex(offset));
    }
    uint64_t median_ts = Common::medianValue(timestamps);
    if (b.timestamp < median_ts) {
        b.timestamp = median_ts;
    }
  }

  size_t medianSize = calculateCumulativeBlocksizeLimit(height) / 2;

  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  uint64_t alreadyGeneratedCoins = chainsLeaves[0]->getAlreadyGeneratedCoins();

  size_t transactionsSize;
  uint64_t fee;
  fillBlockTemplate(b, medianSize, currency.maxBlockCumulativeSize(height), transactionsSize, fee);

  /*
     two-phase miner transaction generation: we don't know exact block size until we prepare block, but we don't know
     reward until we know
     block size, so first miner transaction generated with fake amount of money, and with phase we know think we know
     expected block size
  */
  // make blocks coin-base tx looks close to real coinbase tx to get truthful blob size
  bool r = currency.constructMinerTx(b.majorVersion, height, medianSize, alreadyGeneratedCoins, transactionsSize, fee, adr,
                                     b.baseTransaction, extraNonce, 14);
  if (!r) {
    logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to construct miner tx, first chance";
    return false;
  }

  size_t cumulativeSize = transactionsSize + getObjectBinarySize(b.baseTransaction);
  const size_t TRIES_COUNT = 10;
  for (size_t tryCount = 0; tryCount < TRIES_COUNT; ++tryCount) {
    r = currency.constructMinerTx(b.majorVersion, height, medianSize, alreadyGeneratedCoins, cumulativeSize, fee, adr,
                                  b.baseTransaction, extraNonce, 14);
    if (!r) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to construct miner tx, second chance";
      return false;
    }

    size_t coinbaseBlobSize = getObjectBinarySize(b.baseTransaction);
    if (coinbaseBlobSize > cumulativeSize - transactionsSize) {
      cumulativeSize = transactionsSize + coinbaseBlobSize;
      continue;
    }

    if (coinbaseBlobSize < cumulativeSize - transactionsSize) {
      size_t delta = cumulativeSize - transactionsSize - coinbaseBlobSize;
      b.baseTransaction.extra.insert(b.baseTransaction.extra.end(), delta, 0);
      // here  could be 1 byte difference, because of extra field counter is varint, and it can become from 1-byte len
      // to 2-bytes len.
      if (cumulativeSize != transactionsSize + getObjectBinarySize(b.baseTransaction)) {
        if (!(cumulativeSize + 1 == transactionsSize + getObjectBinarySize(b.baseTransaction))) {
          logger(Logging::ERROR, Logging::BRIGHT_RED)
              << "unexpected case: cumulative_size=" << cumulativeSize
              << " + 1 is not equal txs_cumulative_size=" << transactionsSize
              << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction);
          return false;
        }

        b.baseTransaction.extra.resize(b.baseTransaction.extra.size() - 1);
        if (cumulativeSize != transactionsSize + getObjectBinarySize(b.baseTransaction)) {
          // fuck, not lucky, -1 makes varint-counter size smaller, in that case we continue to grow with
          // cumulative_size
          logger(Logging::TRACE, Logging::BRIGHT_RED)
              << "Miner tx creation have no luck with delta_extra size = " << delta << " and " << delta - 1;
          cumulativeSize += delta - 1;
          continue;
        }

        logger(Logging::DEBUGGING, Logging::BRIGHT_GREEN)
            << "Setting extra for block: " << b.baseTransaction.extra.size() << ", try_count=" << tryCount;
      }
    }
    if (!(cumulativeSize == transactionsSize + getObjectBinarySize(b.baseTransaction))) {
      logger(Logging::ERROR, Logging::BRIGHT_RED)
          << "unexpected case: cumulative_size=" << cumulativeSize
          << " is not equal txs_cumulative_size=" << transactionsSize
          << " + get_object_blobsize(b.baseTransaction)=" << getObjectBinarySize(b.baseTransaction);
      return false;
    }

    return true;
  }

  logger(Logging::ERROR, Logging::BRIGHT_RED) << "Failed to create_block_template with " << TRIES_COUNT << " tries";
  return false;
}

CoreStatistics Core::getCoreStatistics() const {
  // TODO: implement it
  assert(false);
  CoreStatistics result;
  std::fill(reinterpret_cast<uint8_t*>(&result), reinterpret_cast<uint8_t*>(&result) + sizeof(result), 0);
  return result;
}

size_t Core::getPoolTransactionCount() const {
  throwIfNotInitialized();
  return transactionPool->getTransactionCount();
}

size_t Core::getBlockchainTransactionCount() const {
  throwIfNotInitialized();
  IBlockchainCache* mainChain = chainsLeaves[0];
  return mainChain->getTransactionCount();
}

size_t Core::getAlternativeBlockCount() const {
  throwIfNotInitialized();

  using Ptr = decltype(chainsStorage)::value_type;
  return std::accumulate(chainsStorage.begin(), chainsStorage.end(), size_t(0), [&](size_t sum, const Ptr& ptr) {
    return mainChainSet.count(ptr.get()) == 0 ? sum + ptr->getBlockCount() : sum;
  });
}

uint64_t Core::getTotalGeneratedAmount() const {
  assert(!chainsLeaves.empty());
  throwIfNotInitialized();

  return chainsLeaves[0]->getAlreadyGeneratedCoins();
}

std::vector<BlockTemplate> Core::getAlternativeBlocks() const {
  throwIfNotInitialized();

  std::vector<BlockTemplate> alternativeBlocks;
  for (auto& cache : chainsStorage) {
    if (mainChainSet.count(cache.get()))
      continue;
    for (auto index = cache->getStartBlockIndex(); index <= cache->getTopBlockIndex(); ++index) {
      // TODO: optimize
      alternativeBlocks.push_back(fromBinaryArray<BlockTemplate>(cache->getBlockByIndex(index).block));
    }
  }

  return alternativeBlocks;
}

std::vector<Transaction> Core::getPoolTransactions() const {
  throwIfNotInitialized();

  std::vector<Transaction> transactions;
  auto hashes = transactionPool->getPoolTransactions();
  std::transform(std::begin(hashes), std::end(hashes), std::back_inserter(transactions),
                 [&](const CachedTransaction& tx) { return tx.getTransaction(); });
  return transactions;
}

std::vector<std::pair<Transaction, uint64_t>> Core::getPoolTransactionsWithReceiveTime() const {
  throwIfNotInitialized();

  std::vector<std::pair<Transaction, uint64_t>> transactionsWithreceiveTimes;
  std::vector<Transaction> transactions;
  auto hashes = transactionPool->getPoolTransactions();
  std::transform(std::begin(hashes), std::end(hashes), std::back_inserter(transactions),
      [&](const CachedTransaction& tx) { return tx.getTransaction(); });
  for (size_t i = 0; i < transactions.size(); ++i) {
    uint64_t receiveTime = transactionPool->getTransactionReceiveTime(hashes[i].getTransactionHash());
	auto p = std::make_pair(transactions[i], receiveTime);
	transactionsWithreceiveTimes.push_back(p);
  }

  return transactionsWithreceiveTimes;
}

bool Core::extractTransactions(const std::vector<BinaryArray>& rawTransactions,
                               std::vector<CachedTransaction>& transactions, uint64_t& cumulativeSize) {
  try {
    for (auto& rawTransaction : rawTransactions) {
      if (rawTransaction.size() > currency.maxTxSize()) {
        logger(Logging::INFO) << "Raw transaction size " << rawTransaction.size() << " is too big.";
        return false;
      }

      cumulativeSize += rawTransaction.size();
      transactions.emplace_back(rawTransaction);
    }
  } catch (std::runtime_error& e) {
    logger(Logging::INFO) << e.what();
    return false;
  }

  return true;
}

std::error_code Core::validateTransaction(const CachedTransaction& cachedTransaction, TransactionValidatorState& state,
                                          IBlockchainCache* cache, uint64_t& fee, uint32_t blockIndex) {
  // TransactionValidatorState currentState;
  const auto& transaction = cachedTransaction.getTransaction();

  auto error_mixin = validateMixin(transaction, blockIndex);
  if (error_mixin != error::TransactionValidationError::VALIDATION_SUCCESS) {
    return error_mixin;
  }

  auto error = validateSemantic(transaction, fee, blockIndex);
  if (error != error::TransactionValidationError::VALIDATION_SUCCESS) {
    return error;
  }

  size_t inputIndex = 0;
  for (const auto& input : transaction.inputs) {
    if (input.type() == typeid(KeyInput)) {
      const KeyInput& in = boost::get<KeyInput>(input);
      if (!state.spentKeyImages.insert(in.keyImage).second) {
        return error::TransactionValidationError::INPUT_KEYIMAGE_ALREADY_SPENT;
      }

      if (!checkpoints.isInCheckpointZone(blockIndex + 1)) {
        if (cache->checkIfSpent(in.keyImage, blockIndex)) {
          return error::TransactionValidationError::INPUT_KEYIMAGE_ALREADY_SPENT;
        }

        std::vector<PublicKey> outputKeys;
        assert(!in.outputIndexes.empty());

        std::vector<uint32_t> globalIndexes(in.outputIndexes.size());
        globalIndexes[0] = in.outputIndexes[0];
        for (size_t i = 1; i < in.outputIndexes.size(); ++i) {
          globalIndexes[i] = globalIndexes[i - 1] + in.outputIndexes[i];
        }

        auto result = cache->extractKeyOutputKeys(in.amount, blockIndex, {globalIndexes.data(), globalIndexes.size()}, outputKeys);
        if (result == ExtractOutputKeysResult::INVALID_GLOBAL_INDEX) {
          return error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX;
        }

        if (result == ExtractOutputKeysResult::OUTPUT_LOCKED) {
          return error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT;
        }

        if (outputKeys.size() != cachedTransaction.getTransaction().signatures[inputIndex].size())
        {
          return error::TransactionValidationError::INPUT_INVALID_SIGNATURES_COUNT;
        }

        std::vector<const Crypto::PublicKey*> outputKeyPointers;
        outputKeyPointers.reserve(outputKeys.size());
        std::for_each(outputKeys.begin(), outputKeys.end(), [&outputKeyPointers] (const Crypto::PublicKey& key) { outputKeyPointers.push_back(&key); });
        if (!Crypto::check_ring_signature(cachedTransaction.getTransactionPrefixHash(), in.keyImage, outputKeyPointers.data(),
                                          outputKeyPointers.size(), transaction.signatures[inputIndex].data(),
                                          blockIndex > parameters::KEY_IMAGE_CHECKING_BLOCK_INDEX)) {
          return error::TransactionValidationError::INPUT_INVALID_SIGNATURES;
        }
      }

    } else if (input.type() == typeid(MultisignatureInput)) {
      const MultisignatureInput& in = boost::get<MultisignatureInput>(input);
      MultisignatureOutput output;
      uint64_t unlockTime = 0;
      if (!state.spentMultisignatureGlobalIndexes.insert(std::make_pair(in.amount, in.outputIndex)).second) {
        return error::TransactionValidationError::INPUT_MULTISIGNATURE_ALREADY_SPENT;
      }

      if (!cache->getMultisignatureOutputIfExists(in.amount, in.outputIndex, blockIndex, output, unlockTime)) {
        return error::TransactionValidationError::INPUT_INVALID_GLOBAL_INDEX;
      }

      if (cache->checkIfSpentMultisignature(in.amount, in.outputIndex, blockIndex)) {
        return error::TransactionValidationError::INPUT_MULTISIGNATURE_ALREADY_SPENT;
      }

      if (!cache->isTransactionSpendTimeUnlocked(unlockTime, blockIndex)) {
        return error::TransactionValidationError::INPUT_SPEND_LOCKED_OUT;
      }

      if (output.requiredSignatureCount != in.signatureCount) {
        return error::TransactionValidationError::INPUT_WRONG_SIGNATURES_COUNT;
      }

      size_t inputSignatureIndex = 0;
      size_t outputKeyIndex = 0;
      while (inputSignatureIndex < in.signatureCount) {
        if (outputKeyIndex == output.keys.size()) {
          return error::TransactionValidationError::INPUT_INVALID_SIGNATURES;
        }

        if (Crypto::check_signature(cachedTransaction.getTransactionPrefixHash(), output.keys[outputKeyIndex],
                                    transaction.signatures[inputIndex][inputSignatureIndex])) {
          ++inputSignatureIndex;
        }

        ++outputKeyIndex;
      }

    } else {
      assert(false);
      return error::TransactionValidationError::INPUT_UNKNOWN_TYPE;
    }

    inputIndex++;
  }

  return error::TransactionValidationError::VALIDATION_SUCCESS;
}

bool Core::getMixin(const Transaction& transaction, uint64_t& mixin) {
  mixin = 0;
  for (const TransactionInput& txin : transaction.inputs) {
    if (txin.type() != typeid(KeyInput)) {
      continue;
    }
    uint64_t currentMixin = boost::get<KeyInput>(txin).outputIndexes.size();
    if (currentMixin > mixin) {
      mixin = currentMixin;
    }
  }
  return true;
}

// Note that the mixin calculated here is by 1 more than the mixin users input in transaction.
std::error_code Core::validateMixin(const Transaction& transaction, uint32_t blockIndex) {
  uint64_t mixin = 0;
  getMixin(transaction, mixin);
  if ((blockIndex > currency.upgradeHeightV4() && mixin > currency.maxMixin()) ||
      (blockIndex > currency.upgradeHeightV4() && mixin < currency.minMixin() && mixin != 1)) {
    return error::TransactionValidationError::INVALID_MIXIN;
  }
  return error::TransactionValidationError::VALIDATION_SUCCESS;
}

std::error_code Core::validateSemantic(const Transaction& transaction, uint64_t& fee, uint32_t blockIndex) {
  if (transaction.inputs.empty()) {
    return error::TransactionValidationError::EMPTY_INPUTS;
  }

  uint64_t summaryOutputAmount = 0;
  for (const auto& output : transaction.outputs) {
    if (output.amount == 0) {
      return error::TransactionValidationError::OUTPUT_ZERO_AMOUNT;
    }

    if (!is_valid_decomposed_amount(output.amount) && blockIndex >= CryptoNote::parameters::UPGRADE_HEIGHT_V5) {
      return error::TransactionValidationError::OUTPUT_INVALID_DECOMPOSED_AMOUNT;
    }

    if (output.target.type() == typeid(KeyOutput)) {
      if (!check_key(boost::get<KeyOutput>(output.target).key)) {
        return error::TransactionValidationError::OUTPUT_INVALID_KEY;
      }
    } else if (output.target.type() == typeid(MultisignatureOutput)) {
      const MultisignatureOutput& multisignatureOutput = ::boost::get<MultisignatureOutput>(output.target);
      if (multisignatureOutput.requiredSignatureCount > multisignatureOutput.keys.size()) {
        return error::TransactionValidationError::OUTPUT_INVALID_REQUIRED_SIGNATURES_COUNT;
      }

      for (const PublicKey& key : multisignatureOutput.keys) {
        if (!check_key(key)) {
          return error::TransactionValidationError::OUTPUT_INVALID_MULTISIGNATURE_KEY;
        }
      }
    } else {
      return error::TransactionValidationError::OUTPUT_UNKNOWN_TYPE;
    }

    if (std::numeric_limits<uint64_t>::max() - output.amount < summaryOutputAmount) {
      return error::TransactionValidationError::OUTPUTS_AMOUNT_OVERFLOW;
    }

    summaryOutputAmount += output.amount;
  }

  // parameters used for the additional key_image check
  static const Crypto::KeyImage I = { {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };
  static const Crypto::KeyImage L = { {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } };

  uint64_t summaryInputAmount = 0;
  std::unordered_set<Crypto::KeyImage> ki;
  std::set<std::pair<uint64_t, uint32_t>> outputsUsage;
  for (const auto& input : transaction.inputs) {
    uint64_t amount = 0;
    if (input.type() == typeid(KeyInput)) {
      const KeyInput& in = boost::get<KeyInput>(input);
      amount = in.amount;
      if (!ki.insert(in.keyImage).second) {
        return error::TransactionValidationError::INPUT_IDENTICAL_KEYIMAGES;
      }

      if (in.outputIndexes.empty()) {
        return error::TransactionValidationError::INPUT_EMPTY_OUTPUT_USAGE;
      }

      // additional key_image check
      // Fix discovered by Monero Lab and suggested by "fluffypony" (bitcointalk.org)
      if (!(scalarmultKey(in.keyImage, L) == I)) {
        logger(Logging::ERROR) << "Transaction uses key image not in the valid domain";
        return error::TransactionValidationError::INPUT_INVALID_DOMAIN_KEYIMAGES;
      }

      // outputIndexes are packed here, first is absolute, others are offsets to previous,
      // so first can be zero, others can't

      if (std::find(++std::begin(in.outputIndexes), std::end(in.outputIndexes), 0) != std::end(in.outputIndexes)) {
        return error::TransactionValidationError::INPUT_IDENTICAL_OUTPUT_INDEXES;
      }
    } else if (input.type() == typeid(MultisignatureInput)) {
      const MultisignatureInput& in = boost::get<MultisignatureInput>(input);
      amount = in.amount;
      if (!outputsUsage.insert(std::make_pair(in.amount, in.outputIndex)).second) {
        return error::TransactionValidationError::INPUT_IDENTICAL_OUTPUT_INDEXES;
      }
    } else {
      return error::TransactionValidationError::INPUT_UNKNOWN_TYPE;
    }

    if (std::numeric_limits<uint64_t>::max() - amount < summaryInputAmount) {
      return error::TransactionValidationError::INPUTS_AMOUNT_OVERFLOW;
    }

    summaryInputAmount += amount;
  }

  if (summaryOutputAmount > summaryInputAmount) {
    return error::TransactionValidationError::WRONG_AMOUNT;
  }

  assert(transaction.signatures.size() == transaction.inputs.size());
  fee = summaryInputAmount - summaryOutputAmount;

  CachedTransaction cachedTransaction(std::move(transaction));
  bool isFusion = fee == 0 && currency.isFusionTransaction(transaction, cachedTransaction.getTransactionBinaryArray().size(), blockIndex);
  if (!isFusion && (blockIndex < CryptoNote::parameters::UPGRADE_HEIGHT_V4 ? (fee < currency.minimumFee()) :
    (fee < (getMinimalFeeForHeight(blockIndex) - (getMinimalFeeForHeight(blockIndex) * 20 / 100))))) {
    return error::TransactionValidationError::INVALID_FEE;
  }

  return error::TransactionValidationError::VALIDATION_SUCCESS;
}

uint32_t Core::findBlockchainSupplement(const std::vector<Crypto::Hash>& remoteBlockIds) const {
  // TODO: check for genesis blocks match
  for (auto& hash : remoteBlockIds) {
    IBlockchainCache* blockchainSegment = findMainChainSegmentContainingBlock(hash);
    if (blockchainSegment != nullptr) {
      return blockchainSegment->getBlockIndex(hash);
    }
  }

  throw std::runtime_error("Genesis block hash was not found.");
}

std::vector<Crypto::Hash> CryptoNote::Core::getBlockHashes(uint32_t startBlockIndex, uint32_t maxCount) const {
  return chainsLeaves[0]->getBlockHashes(startBlockIndex, maxCount);
}

std::error_code Core::validateBlock(const CachedBlock& cachedBlock, IBlockchainCache* cache, uint64_t& minerReward) {
  const auto& block = cachedBlock.getBlock();
  auto previousBlockIndex = cache->getBlockIndex(block.previousBlockHash);
  // assert(block.previousBlockHash == cache->getBlockHash(previousBlockIndex));

  minerReward = 0;

  if (upgradeManager->getBlockMajorVersion(cachedBlock.getBlockIndex()) != block.majorVersion) {
    return error::BlockValidationError::WRONG_VERSION;
  }

  if (block.majorVersion == BLOCK_MAJOR_VERSION_2 || block.majorVersion == BLOCK_MAJOR_VERSION_3) {
    if (block.majorVersion == BLOCK_MAJOR_VERSION_2 && block.parentBlock.majorVersion > BLOCK_MAJOR_VERSION_1) {
      logger(Logging::ERROR, Logging::BRIGHT_RED) << "Parent block of block " << cachedBlock.getBlockHash() << " has wrong major version: "
                                << static_cast<int>(block.parentBlock.majorVersion) << ", at index " << cachedBlock.getBlockIndex()
                                << " expected version is " << static_cast<int>(BLOCK_MAJOR_VERSION_1);
      return error::BlockValidationError::PARENT_BLOCK_WRONG_VERSION;
    }

    if (cachedBlock.getParentBlockBinaryArray(false).size() > 2048) {
      return error::BlockValidationError::PARENT_BLOCK_SIZE_TOO_BIG;
    }
  }

  if (block.timestamp > getAdjustedTime() + currency.blockFutureTimeLimit(block.majorVersion)) {
    return error::BlockValidationError::TIMESTAMP_TOO_FAR_IN_FUTURE;
  }

  auto timestamps = cache->getLastTimestamps(currency.timestampCheckWindow(block.majorVersion), previousBlockIndex, addGenesisBlock);
  if (timestamps.size() >= currency.timestampCheckWindow(block.majorVersion)) {
    auto median_ts = Common::medianValue(timestamps);
    if (block.timestamp < median_ts) {
      return error::BlockValidationError::TIMESTAMP_TOO_FAR_IN_PAST;
    }
  }

  if (block.baseTransaction.inputs.size() != 1) {
    return error::TransactionValidationError::INPUT_WRONG_COUNT;
  }

  if (block.baseTransaction.inputs[0].type() != typeid(BaseInput)) {
    return error::TransactionValidationError::INPUT_UNEXPECTED_TYPE;
  }

  if (boost::get<BaseInput>(block.baseTransaction.inputs[0]).blockIndex != previousBlockIndex + 1) {
    return error::TransactionValidationError::BASE_INPUT_WRONG_BLOCK_INDEX;
  }

  if (!(block.baseTransaction.unlockTime == previousBlockIndex + 1 + (block.majorVersion < CryptoNote::BLOCK_MAJOR_VERSION_5 ? currency.minedMoneyUnlockWindow() : currency.minedMoneyUnlockWindow_v1()))) {
    return error::TransactionValidationError::WRONG_TRANSACTION_UNLOCK_TIME;
  }

  if (!block.baseTransaction.signatures.empty())
  {
    return error::TransactionValidationError::BASE_INVALID_SIGNATURES_COUNT;
  }

  for (const auto& output : block.baseTransaction.outputs) {
    if (output.amount == 0) {
      return error::TransactionValidationError::OUTPUT_ZERO_AMOUNT;
    }

    if (output.target.type() == typeid(KeyOutput)) {
      if (!check_key(boost::get<KeyOutput>(output.target).key)) {
        return error::TransactionValidationError::OUTPUT_INVALID_KEY;
      }
    } else if (output.target.type() == typeid(MultisignatureOutput)) {
      const MultisignatureOutput& multisignatureOutput = ::boost::get<MultisignatureOutput>(output.target);
      if (multisignatureOutput.requiredSignatureCount > multisignatureOutput.keys.size()) {
        return error::TransactionValidationError::OUTPUT_INVALID_REQUIRED_SIGNATURES_COUNT;
      }

      for (const PublicKey& key : multisignatureOutput.keys) {
        if (!check_key(key)) {
          return error::TransactionValidationError::OUTPUT_INVALID_MULTISIGNATURE_KEY;
        }
      }
    } else {
      return error::TransactionValidationError::OUTPUT_UNKNOWN_TYPE;
    }

    if (std::numeric_limits<uint64_t>::max() - output.amount < minerReward) {
      return error::TransactionValidationError::OUTPUTS_AMOUNT_OVERFLOW;
    }

    minerReward += output.amount;
  }

  return error::BlockValidationError::VALIDATION_SUCCESS;
}

uint64_t CryptoNote::Core::getAdjustedTime() const {
  return time(NULL);
}

const Currency& Core::getCurrency() const {
  return currency;
}

void Core::save() {
  throwIfNotInitialized();

  deleteAlternativeChains();
  mergeMainChainSegments();
  chainsLeaves[0]->save();
}

void Core::load() {
  initRootSegment();

  start_time = std::time(nullptr);

  auto dbBlocksCount = chainsLeaves[0]->getTopBlockIndex() + 1;
  auto storageBlocksCount = mainChainStorage->getBlockCount();

  logger(Logging::DEBUGGING) << "Blockchain storage blocks count: " << storageBlocksCount << ", DB blocks count: " << dbBlocksCount;

  assert(storageBlocksCount != 0); //we assume the storage has at least genesis block

  if (storageBlocksCount > dbBlocksCount) {
    logger(Logging::INFO) << "Importing blocks from blockchain storage";
    importBlocksFromStorage();
  } else if (storageBlocksCount < dbBlocksCount) {
    auto cutFrom = findCommonRoot(*mainChainStorage, *chainsLeaves[0]) + 1;

    logger(Logging::INFO) << "DB has more blocks than blockchain storage, cutting from block index: " << cutFrom;
    cutSegment(*chainsLeaves[0], cutFrom);

    assert(chainsLeaves[0]->getTopBlockIndex() + 1 == mainChainStorage->getBlockCount());
  } else if (getBlockHash(mainChainStorage->getBlockByIndex(storageBlocksCount - 1)) != chainsLeaves[0]->getTopBlockHash()) {
    logger(Logging::INFO) << "Blockchain storage and root segment are on different chains. "
                             << "Cutting root segment to common block index " << findCommonRoot(*mainChainStorage, *chainsLeaves[0]) << " and reimporting blocks";
    importBlocksFromStorage();
  } else {
    logger(Logging::DEBUGGING) << "Blockchain storage and root segment are on the same height and chain";
  }

  initialized = true;
}

void Core::initRootSegment() {
  std::unique_ptr<IBlockchainCache> cache = this->blockchainCacheFactory->createRootBlockchainCache(currency);

  mainChainSet.emplace(cache.get());

  chainsLeaves.push_back(cache.get());
  chainsStorage.push_back(std::move(cache));

  contextGroup.spawn(std::bind(&Core::transactionPoolCleaningProcedure, this));

  updateBlockMedianSize();

  chainsLeaves[0]->load();
}

void Core::importBlocksFromStorage() {
  uint32_t commonIndex = findCommonRoot(*mainChainStorage, *chainsLeaves[0]);
  assert(commonIndex <= mainChainStorage->getBlockCount());

  cutSegment(*chainsLeaves[0], commonIndex + 1);

  auto previousBlockHash = getBlockHash(mainChainStorage->getBlockByIndex(commonIndex));
  auto blockCount = mainChainStorage->getBlockCount();
  for (uint32_t i = commonIndex + 1; i < blockCount; ++i) {
    RawBlock rawBlock = mainChainStorage->getBlockByIndex(i);
    auto blockTemplate = extractBlockTemplate(rawBlock);
    CachedBlock cachedBlock(blockTemplate);

    if (blockTemplate.previousBlockHash != previousBlockHash) {
      logger(Logging::ERROR) << "Corrupted blockchain. Block with index " << i << " and hash " << cachedBlock.getBlockHash()
                             << " has previous block hash " << blockTemplate.previousBlockHash << ", but parent has hash " << previousBlockHash
                             << ". Resynchronize your daemon please.";
      throw std::system_error(make_error_code(error::CoreErrorCode::CORRUPTED_BLOCKCHAIN));
    }

    previousBlockHash = cachedBlock.getBlockHash();

    std::vector<CachedTransaction> transactions;
    uint64_t cumulativeSize = 0;
    if (!extractTransactions(rawBlock.transactions, transactions, cumulativeSize)) {
      logger(Logging::ERROR) << "Couldn't deserialize raw block transactions in block " << cachedBlock.getBlockHash();
      throw std::system_error(make_error_code(error::AddBlockErrorCode::DESERIALIZATION_FAILED));
    }

    cumulativeSize += getObjectBinarySize(blockTemplate.baseTransaction);
    TransactionValidatorState spentOutputs = extractSpentOutputs(transactions);
    auto currentDifficulty = chainsLeaves[0]->getDifficultyForNextBlock(i - 1);

    uint64_t cumulativeFee = std::accumulate(transactions.begin(), transactions.end(), UINT64_C(0), [] (uint64_t fee, const CachedTransaction& transaction) {
      return fee + transaction.getTransactionFee();
    });

    int64_t emissionChange = getEmissionChange(currency, *chainsLeaves[0], i - 1, cachedBlock, cumulativeSize, cumulativeFee);
    chainsLeaves[0]->pushBlock(cachedBlock, transactions, spentOutputs, cumulativeSize, emissionChange, currentDifficulty, std::move(rawBlock));

    if (i % 1000 == 0) {
      logger(Logging::INFO) << "Imported block with index " << i << " / " << (blockCount - 1);
    }
  }
}

void Core::cutSegment(IBlockchainCache& segment, uint32_t startIndex) {
  if (segment.getTopBlockIndex() < startIndex) {
    return;
  }

  logger(Logging::INFO) << "Cutting root segment from index " << startIndex;
  auto childCache = segment.split(startIndex);
  segment.deleteChild(childCache.get());
}

void Core::updateMainChainSet() {
  mainChainSet.clear();
  IBlockchainCache* chainPtr = chainsLeaves[0];
  assert(chainPtr != nullptr);
  do {
    mainChainSet.insert(chainPtr);
    chainPtr = chainPtr->getParent();
  } while (chainPtr != nullptr);
}

IBlockchainCache* Core::findSegmentContainingBlock(const Crypto::Hash& blockHash) const {
  assert(chainsLeaves.size() > 0);

  // first search in main chain
  auto blockSegment = findMainChainSegmentContainingBlock(blockHash);
  if (blockSegment != nullptr) {
    return blockSegment;
  }

  // then search in alternative chains
  return findAlternativeSegmentContainingBlock(blockHash);
}

IBlockchainCache* Core::findSegmentContainingBlock(uint32_t blockHeight) const {
  assert(chainsLeaves.size() > 0);

  // first search in main chain
  auto blockSegment = findMainChainSegmentContainingBlock(blockHeight);
  if (blockSegment != nullptr) {
    return blockSegment;
  }

  // then search in alternative chains
  return findAlternativeSegmentContainingBlock(blockHeight);
}

IBlockchainCache* Core::findAlternativeSegmentContainingBlock(const Crypto::Hash& blockHash) const {
  IBlockchainCache* cache = nullptr;
  std::find_if(++chainsLeaves.begin(), chainsLeaves.end(),
               [&](IBlockchainCache* chain) { return cache = findIndexInChain(chain, blockHash); });
  return cache;
}

IBlockchainCache* Core::findMainChainSegmentContainingBlock(const Crypto::Hash& blockHash) const {
  return findIndexInChain(chainsLeaves[0], blockHash);
}

IBlockchainCache* Core::findMainChainSegmentContainingBlock(uint32_t blockIndex) const {
  return findIndexInChain(chainsLeaves[0], blockIndex);
}

// WTF?! this function returns first chain it is able to find..
IBlockchainCache* Core::findAlternativeSegmentContainingBlock(uint32_t blockIndex) const {
  IBlockchainCache* cache = nullptr;
  std::find_if(++chainsLeaves.begin(), chainsLeaves.end(),
               [&](IBlockchainCache* chain) { return cache = findIndexInChain(chain, blockIndex); });
  return nullptr;
}

BlockTemplate Core::restoreBlockTemplate(IBlockchainCache* blockchainCache, uint32_t blockIndex) const {
  RawBlock rawBlock = blockchainCache->getBlockByIndex(blockIndex);

  BlockTemplate block;
  if (!fromBinaryArray(block, rawBlock.block)) {
    throw std::runtime_error("Coulnd't deserialize BlockTemplate");
  }

  return block;
}

std::vector<Crypto::Hash> Core::doBuildSparseChain(const Crypto::Hash& blockHash) const {
  IBlockchainCache* chain = findSegmentContainingBlock(blockHash);

  uint32_t blockIndex = chain->getBlockIndex(blockHash);

  // TODO reserve ceil(log(blockIndex))
  std::vector<Crypto::Hash> sparseChain;
  sparseChain.push_back(blockHash);

  for (uint32_t i = 1; i < blockIndex; i *= 2) {
    sparseChain.push_back(chain->getBlockHash(blockIndex - i));
  }

  auto genesisBlockHash = chain->getBlockHash(0);
  if (sparseChain[0] != genesisBlockHash) {
    sparseChain.push_back(genesisBlockHash);
  }

  return sparseChain;
}

RawBlock Core::getRawBlock(IBlockchainCache* segment, uint32_t blockIndex) const {
  assert(blockIndex >= segment->getStartBlockIndex() && blockIndex <= segment->getTopBlockIndex());

  return segment->getBlockByIndex(blockIndex);
}

//TODO: decompose these two methods
size_t Core::pushBlockHashes(uint32_t startIndex, uint32_t fullOffset, size_t maxItemsCount,
                             std::vector<BlockShortInfo>& entries) const {
  assert(fullOffset >= startIndex);

  uint32_t itemsCount = std::min(fullOffset - startIndex, static_cast<uint32_t>(maxItemsCount));
  if (itemsCount == 0) {
    return 0;
  }

  std::vector<Crypto::Hash> blockIds = getBlockHashes(startIndex, itemsCount);

  entries.reserve(entries.size() + blockIds.size());
  for (auto& blockHash : blockIds) {
    BlockShortInfo entry;
    entry.blockId = std::move(blockHash);
    entries.emplace_back(std::move(entry));
  }

  return blockIds.size();
}

//TODO: decompose these two methods
size_t Core::pushBlockHashes(uint32_t startIndex, uint32_t fullOffset, size_t maxItemsCount,
                             std::vector<BlockFullInfo>& entries) const {
  assert(fullOffset >= startIndex);

  uint32_t itemsCount = std::min(fullOffset - startIndex, static_cast<uint32_t>(maxItemsCount));
  if (itemsCount == 0) {
    return 0;
  }

  std::vector<Crypto::Hash> blockIds = getBlockHashes(startIndex, itemsCount);

  entries.reserve(entries.size() + blockIds.size());
  for (auto& blockHash : blockIds) {
    BlockFullInfo entry;
    entry.block_id = std::move(blockHash);
    entries.emplace_back(std::move(entry));
  }

  return blockIds.size();
}

void Core::fillQueryBlockFullInfo(uint32_t fullOffset, uint32_t currentIndex, size_t maxItemsCount,
                                  std::vector<BlockFullInfo>& entries) const {
  assert(currentIndex >= fullOffset);

  uint32_t fullBlocksCount =
      static_cast<uint32_t>(std::min(static_cast<uint32_t>(maxItemsCount), currentIndex - fullOffset));
  entries.reserve(entries.size() + fullBlocksCount);

  for (uint32_t blockIndex = fullOffset; blockIndex < fullOffset + fullBlocksCount; ++blockIndex) {
    IBlockchainCache* segment = findMainChainSegmentContainingBlock(blockIndex);

    BlockFullInfo blockFullInfo;
    blockFullInfo.block_id = segment->getBlockHash(blockIndex);
    static_cast<RawBlock&>(blockFullInfo) = getRawBlock(segment, blockIndex);

    entries.emplace_back(std::move(blockFullInfo));
  }
}

void Core::fillQueryBlockShortInfo(uint32_t fullOffset, uint32_t currentIndex, size_t maxItemsCount,
                                   std::vector<BlockShortInfo>& entries) const {
  assert(currentIndex >= fullOffset);

  uint32_t fullBlocksCount = static_cast<uint32_t>(std::min(static_cast<uint32_t>(maxItemsCount), currentIndex - fullOffset + 1));
  entries.reserve(entries.size() + fullBlocksCount);

  for (uint32_t blockIndex = fullOffset; blockIndex < fullOffset + fullBlocksCount; ++blockIndex) {
    IBlockchainCache* segment = findMainChainSegmentContainingBlock(blockIndex);
    RawBlock rawBlock = getRawBlock(segment, blockIndex);

    BlockShortInfo blockShortInfo;
    blockShortInfo.block = std::move(rawBlock.block);
    blockShortInfo.blockId = segment->getBlockHash(blockIndex);

    blockShortInfo.txPrefixes.reserve(rawBlock.transactions.size());
    for (auto& rawTransaction : rawBlock.transactions) {
      TransactionPrefixInfo prefixInfo;
      prefixInfo.txHash =
          getBinaryArrayHash(rawTransaction); // TODO: is there faster way to get hash without calculation?

      Transaction transaction;
      if (!fromBinaryArray(transaction, rawTransaction)) {
        // TODO: log it
        throw std::runtime_error("Couldn't deserialize transaction");
      }

      prefixInfo.txPrefix = std::move(static_cast<TransactionPrefix&>(transaction));
      blockShortInfo.txPrefixes.emplace_back(std::move(prefixInfo));
    }

    entries.emplace_back(std::move(blockShortInfo));
  }
}

void Core::getTransactionPoolDifference(const std::vector<Crypto::Hash>& knownHashes,
                                        std::vector<Crypto::Hash>& newTransactions,
                                        std::vector<Crypto::Hash>& deletedTransactions) const {
  auto t = transactionPool->getTransactionHashes();

  std::unordered_set<Crypto::Hash> poolTransactions(t.begin(), t.end());
  std::unordered_set<Crypto::Hash> knownTransactions(knownHashes.begin(), knownHashes.end());

  for (auto it = poolTransactions.begin(), end = poolTransactions.end(); it != end;) {
    auto knownTransactionIt = knownTransactions.find(*it);
    if (knownTransactionIt != knownTransactions.end()) {
      knownTransactions.erase(knownTransactionIt);
      it = poolTransactions.erase(it);
    } else {
      ++it;
    }
  }

  newTransactions.assign(poolTransactions.begin(), poolTransactions.end());
  deletedTransactions.assign(knownTransactions.begin(), knownTransactions.end());
}

uint8_t Core::getBlockMajorVersionForHeight(uint32_t height) const {
  return upgradeManager->getBlockMajorVersion(height);
}

size_t Core::calculateCumulativeBlocksizeLimit(uint32_t height) const {
  uint8_t nextBlockMajorVersion = getBlockMajorVersionForHeight(height);
  size_t nextBlockGrantedFullRewardZone = currency.blockGrantedFullRewardZoneByBlockVersion(nextBlockMajorVersion);

  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());
  // FIXME: skip gensis here?
  auto sizes = chainsLeaves[0]->getLastBlocksSizes(currency.rewardBlocksWindow());
  uint64_t median = Common::medianValue(sizes);
  if (median <= nextBlockGrantedFullRewardZone) {
    median = nextBlockGrantedFullRewardZone;
  }

  return median * 2;
}

void Core::fillBlockTemplate(BlockTemplate& block, size_t medianSize, size_t maxCumulativeSize,
                             size_t& transactionsSize, uint64_t& fee) const {
  transactionsSize = 0;
  fee = 0;

  size_t maxTotalSize = (125 * medianSize) / 100;
  maxTotalSize = std::min(maxTotalSize, maxCumulativeSize) - currency.minerTxBlobReservedSize();

  TransactionSpentInputsChecker spentInputsChecker;

  std::vector<CachedTransaction> poolTransactions = transactionPool->getPoolTransactions();
  for (auto it = poolTransactions.rbegin(); it != poolTransactions.rend() && it->getTransactionFee() == 0; ++it) {
    const CachedTransaction& transaction = *it;

    auto transactionBlobSize = transaction.getTransactionBinaryArray().size();
    if (currency.fusionTxMaxSize() < transactionsSize + transactionBlobSize) {
      continue;
    }

    if (!spentInputsChecker.haveSpentInputs(transaction.getTransaction())) {
      block.transactionHashes.emplace_back(transaction.getTransactionHash());
      transactionsSize += transactionBlobSize;
      logger(Logging::TRACE) << "Fusion transaction " << transaction.getTransactionHash() << " included to block template";
    }
  }

  for (const auto& cachedTransaction : poolTransactions) {
    size_t blockSizeLimit = (cachedTransaction.getTransactionFee() == 0) ? medianSize : maxTotalSize;

    if (blockSizeLimit < transactionsSize + cachedTransaction.getTransactionBinaryArray().size()) {
      continue;
    }

    if (!spentInputsChecker.haveSpentInputs(cachedTransaction.getTransaction())) {
      transactionsSize += cachedTransaction.getTransactionBinaryArray().size();
      fee += cachedTransaction.getTransactionFee();
      block.transactionHashes.emplace_back(cachedTransaction.getTransactionHash());
      logger(Logging::TRACE) << "Transaction " << cachedTransaction.getTransactionHash() << " included to block template";
    } else {
      logger(Logging::TRACE) << "Transaction " << cachedTransaction.getTransactionHash() << " is failed to include to block template";
    }
  }
}

void Core::deleteAlternativeChains() {
  while (chainsLeaves.size() > 1) {
    deleteLeaf(1);
  }
}

void Core::deleteLeaf(size_t leafIndex) {
  assert(leafIndex < chainsLeaves.size());

  IBlockchainCache* leaf = chainsLeaves[leafIndex];

  IBlockchainCache* parent = leaf->getParent();
  if (parent != nullptr) {
    bool r = parent->deleteChild(leaf);
    if (r) {}
    assert(r);
  }

  auto segmentIt =
      std::find_if(chainsStorage.begin(), chainsStorage.end(),
                   [&leaf](const std::unique_ptr<IBlockchainCache>& segment) { return segment.get() == leaf; });

  assert(segmentIt != chainsStorage.end());

  if (leafIndex != 0) {
    if (parent->getChildCount() == 0) {
      chainsLeaves.push_back(parent);
    }

    chainsLeaves.erase(chainsLeaves.begin() + leafIndex);
  } else {
    if (parent != nullptr) {
      chainsLeaves[0] = parent;
    } else {
      chainsLeaves.erase(chainsLeaves.begin());
    }
  }

  chainsStorage.erase(segmentIt);
}

void Core::mergeMainChainSegments() {
  assert(!chainsStorage.empty());
  assert(!chainsLeaves.empty());

  std::vector<IBlockchainCache*> chain;
  IBlockchainCache* segment = chainsLeaves[0];
  while (segment != nullptr) {
    chain.push_back(segment);
    segment = segment->getParent();
  }

  IBlockchainCache* rootSegment = chain.back();
  for (auto it = ++chain.rbegin(); it != chain.rend(); ++it) {
    mergeSegments(rootSegment, *it);
  }

  auto rootIt = std::find_if(
      chainsStorage.begin(), chainsStorage.end(),
      [&rootSegment](const std::unique_ptr<IBlockchainCache>& segment) { return segment.get() == rootSegment; });

  assert(rootIt != chainsStorage.end());

  if (rootIt != chainsStorage.begin()) {
    *chainsStorage.begin() = std::move(*rootIt);
  }

  chainsStorage.erase(++chainsStorage.begin(), chainsStorage.end());
  chainsLeaves.clear();
  chainsLeaves.push_back(chainsStorage.begin()->get());
}

void Core::mergeSegments(IBlockchainCache* acceptingSegment, IBlockchainCache* segment) {
  assert(segment->getStartBlockIndex() == acceptingSegment->getStartBlockIndex() + acceptingSegment->getBlockCount());

  auto startIndex = segment->getStartBlockIndex();
  auto blockCount = segment->getBlockCount();
  for (auto blockIndex = startIndex; blockIndex < startIndex + blockCount; ++blockIndex) {
    PushedBlockInfo info = segment->getPushedBlockInfo(blockIndex);

    BlockTemplate block;
    if (!fromBinaryArray(block, info.rawBlock.block)) {
      logger(Logging::WARNING) << "mergeSegments error: Couldn't deserialize block";
      throw std::runtime_error("Couldn't deserialize block");
    }

    std::vector<CachedTransaction> transactions;
    if (!Utils::restoreCachedTransactions(info.rawBlock.transactions, transactions)) {
      logger(Logging::WARNING) << "mergeSegments error: Couldn't deserialize transactions";
      throw std::runtime_error("Couldn't deserialize transactions");
    }

    acceptingSegment->pushBlock(CachedBlock(block), transactions, info.validatorState, info.blockSize,
                                info.generatedCoins, info.blockDifficulty, std::move(info.rawBlock));
  }
}

BlockDetails Core::getBlockDetails(const uint32_t blockHeight) const {
  throwIfNotInitialized();

  IBlockchainCache* segment = findSegmentContainingBlock(blockHeight);
  if (segment == nullptr) {
    throw std::runtime_error("Requested block height wasn't found in blockchain.");
  }

  return getBlockDetails(segment->getBlockHash(blockHeight));
}

BlockDetails Core::getBlockDetails(const Crypto::Hash& blockHash) const {
  throwIfNotInitialized();

  IBlockchainCache* segment = findSegmentContainingBlock(blockHash);
  if (segment == nullptr) {
    throw std::runtime_error("Requested hash wasn't found in blockchain.");
  }

  uint32_t blockIndex = segment->getBlockIndex(blockHash);
  BlockTemplate blockTemplate = restoreBlockTemplate(segment, blockIndex);
  
  BlockDetails blockDetails;
  blockDetails.majorVersion = blockTemplate.majorVersion;
  blockDetails.minorVersion = blockTemplate.minorVersion;
  blockDetails.timestamp = blockTemplate.timestamp;
  blockDetails.prevBlockHash = blockTemplate.previousBlockHash;
  blockDetails.nonce = blockTemplate.nonce;
  blockDetails.hash = blockHash;

  blockDetails.reward = 0;
  for (const TransactionOutput& out : blockTemplate.baseTransaction.outputs) {
    blockDetails.reward += out.amount;
  }

  blockDetails.index = blockIndex;
  blockDetails.isAlternative = mainChainSet.count(segment) == 0;

  blockDetails.difficulty = getBlockDifficulty(blockIndex);

  std::vector<uint64_t> sizes = segment->getLastBlocksSizes(1, blockDetails.index, addGenesisBlock);
  assert(sizes.size() == 1);
  blockDetails.transactionsCumulativeSize = sizes.front();

  uint64_t blockBlobSize = getObjectBinarySize(blockTemplate);
  uint64_t coinbaseTransactionSize = getObjectBinarySize(blockTemplate.baseTransaction);
  blockDetails.blockSize = blockBlobSize + blockDetails.transactionsCumulativeSize - coinbaseTransactionSize;

  blockDetails.alreadyGeneratedCoins = segment->getAlreadyGeneratedCoins(blockDetails.index);
  blockDetails.alreadyGeneratedTransactions = segment->getAlreadyGeneratedTransactions(blockDetails.index);

  uint64_t prevBlockGeneratedCoins = 0;
  blockDetails.sizeMedian = 0;
  if (blockDetails.index > 0) {
    auto lastBlocksSizes = segment->getLastBlocksSizes(currency.rewardBlocksWindow(), blockDetails.index - 1, addGenesisBlock);
    blockDetails.sizeMedian = Common::medianValue(lastBlocksSizes);
    prevBlockGeneratedCoins = segment->getAlreadyGeneratedCoins(blockDetails.index - 1);
  }

  int64_t emissionChange = 0;
  bool result = currency.getBlockReward(blockDetails.majorVersion, blockDetails.sizeMedian, 0, prevBlockGeneratedCoins, 0, blockDetails.baseReward, emissionChange);
  if (result) {}
  assert(result);

  uint64_t currentReward = 0;
  result = currency.getBlockReward(blockDetails.majorVersion, blockDetails.sizeMedian, blockDetails.transactionsCumulativeSize,
                                   prevBlockGeneratedCoins, 0, currentReward, emissionChange);
  assert(result);

  if (blockDetails.baseReward == 0 && currentReward == 0) {
    blockDetails.penalty = static_cast<double>(0);
  } else {
    assert(blockDetails.baseReward >= currentReward);
    blockDetails.penalty = static_cast<double>(blockDetails.baseReward - currentReward) / static_cast<double>(blockDetails.baseReward);
  }

  blockDetails.transactions.reserve(blockTemplate.transactionHashes.size() + 1);
  CachedTransaction cachedBaseTx(std::move(blockTemplate.baseTransaction));
  blockDetails.transactions.push_back(getTransactionDetails(cachedBaseTx.getTransactionHash(), segment, false));

  blockDetails.totalFeeAmount = 0;
  for (const Crypto::Hash& transactionHash : blockTemplate.transactionHashes) {
    blockDetails.transactions.push_back(getTransactionDetails(transactionHash, segment, false));
    blockDetails.totalFeeAmount += blockDetails.transactions.back().fee;
  }

  return blockDetails;
}

TransactionDetails Core::getTransactionDetails(const Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();

  IBlockchainCache* segment = findSegmentContainingTransaction(transactionHash);
  bool foundInPool = transactionPool->checkIfTransactionPresent(transactionHash);
  if (segment == nullptr && !foundInPool) {
    throw std::runtime_error("Requested transaction wasn't found.");
  }

  return getTransactionDetails(transactionHash, segment, foundInPool);
}

TransactionDetails Core::getTransactionDetails(const Crypto::Hash& transactionHash, IBlockchainCache* segment, bool foundInPool) const {
  assert((segment != nullptr) != foundInPool);
  if (segment == nullptr) {
    segment = chainsLeaves[0];
  }

  std::unique_ptr<ITransaction> transaction;
  Transaction rawTransaction;
  TransactionDetails transactionDetails;
  if (!foundInPool) {
    std::vector<Crypto::Hash> transactionsHashes;
    std::vector<BinaryArray> rawTransactions;
    std::vector<Crypto::Hash> missedTransactionsHashes;
    transactionsHashes.push_back(transactionHash);

    segment->getRawTransactions(transactionsHashes, rawTransactions, missedTransactionsHashes);
    assert(missedTransactionsHashes.empty());
    assert(rawTransactions.size() == 1);

    std::vector<CachedTransaction> transactions;
    Utils::restoreCachedTransactions(rawTransactions, transactions);
    assert(transactions.size() == 1);

    transactionDetails.inBlockchain = true;
    transactionDetails.blockIndex = segment->getBlockIndexContainingTx(transactionHash);
    transactionDetails.blockHash = segment->getBlockHash(transactionDetails.blockIndex);

    auto timestamps = segment->getLastTimestamps(1, transactionDetails.blockIndex, addGenesisBlock);
    assert(timestamps.size() == 1);
    transactionDetails.timestamp = timestamps.back();

    transactionDetails.size = transactions.back().getTransactionBinaryArray().size();
    transactionDetails.fee = transactions.back().getTransactionFee();

    rawTransaction = transactions.back().getTransaction();
    transaction = createTransaction(rawTransaction);
  } else {
    transactionDetails.inBlockchain = false;
    transactionDetails.timestamp = transactionPool->getTransactionReceiveTime(transactionHash);

    transactionDetails.size = transactionPool->getTransaction(transactionHash).getTransactionBinaryArray().size();
    transactionDetails.fee = transactionPool->getTransaction(transactionHash).getTransactionFee();

    rawTransaction = transactionPool->getTransaction(transactionHash).getTransaction();
    transaction = createTransaction(rawTransaction);
  }

  transactionDetails.hash = transactionHash;
  transactionDetails.unlockTime = transaction->getUnlockTime();

  transactionDetails.totalOutputsAmount = transaction->getOutputTotalAmount();
  transactionDetails.totalInputsAmount = transaction->getInputTotalAmount();

  transactionDetails.mixin = 0;
  for (size_t i = 0; i < transaction->getInputCount(); ++i) {
    if (transaction->getInputType(i) != TransactionTypes::InputType::Key) {
      continue;
    }

    KeyInput input;
    transaction->getInput(i, input);
    uint64_t currentMixin = input.outputIndexes.size();
    if (currentMixin > transactionDetails.mixin) {
      transactionDetails.mixin = currentMixin;
    }
  }

  transactionDetails.paymentId = boost::value_initialized<Crypto::Hash>();
  if (transaction->getPaymentId(transactionDetails.paymentId)) {
    transactionDetails.hasPaymentId = true;
  }
  transactionDetails.extra.publicKey = transaction->getTransactionPublicKey();
  transaction->getExtraNonce(transactionDetails.extra.nonce);
  
  transactionDetails.signatures = rawTransaction.signatures;

  transactionDetails.inputs.reserve(transaction->getInputCount());
  for (size_t i = 0; i < transaction->getInputCount(); ++i) {
    TransactionInputDetails txInDetails;

    if (transaction->getInputType(i) == TransactionTypes::InputType::Generating) {
      BaseInputDetails baseDetails;
      baseDetails.input = boost::get<BaseInput>(rawTransaction.inputs[i]);
      baseDetails.amount = transaction->getOutputTotalAmount();
      txInDetails = baseDetails;
    } else if (transaction->getInputType(i) == TransactionTypes::InputType::Key) {
      KeyInputDetails txInToKeyDetails;
      txInToKeyDetails.input = boost::get<KeyInput>(rawTransaction.inputs[i]);
      std::vector<std::pair<Crypto::Hash, size_t>> outputReferences;
      outputReferences.reserve(txInToKeyDetails.input.outputIndexes.size());
      std::vector<uint32_t> globalIndexes = relativeOutputOffsetsToAbsolute(txInToKeyDetails.input.outputIndexes);
      ExtractOutputKeysResult result = segment->extractKeyOtputReferences(txInToKeyDetails.input.amount, { globalIndexes.data(), globalIndexes.size() }, outputReferences);
      if (result == result) {}
      assert(result == ExtractOutputKeysResult::SUCCESS);
      assert(txInToKeyDetails.input.outputIndexes.size() == outputReferences.size());

      txInToKeyDetails.mixin = txInToKeyDetails.input.outputIndexes.size();
      
      for (const auto& r : outputReferences) {
        TransactionOutputReferenceDetails d;
        d.number = r.second;
        d.transactionHash = r.first;
        txInToKeyDetails.outputs.push_back(d);
      }

      txInDetails = txInToKeyDetails;
    } else if (transaction->getInputType(i) == TransactionTypes::InputType::Multisignature) {
      MultisignatureInputDetails txInMultisigDetails;
      txInMultisigDetails.input = boost::get<MultisignatureInput>(rawTransaction.inputs[i]);
      std::pair<Crypto::Hash, size_t> outputReference = segment->getMultisignatureOutputReference(txInMultisigDetails.input.amount, txInMultisigDetails.input.outputIndex);
      
      txInMultisigDetails.output.number = outputReference.second;
      txInMultisigDetails.output.transactionHash = outputReference.first;
      txInDetails = txInMultisigDetails;
    }

    assert(!txInDetails.empty());
    transactionDetails.inputs.push_back(std::move(txInDetails));
  }

  transactionDetails.outputs.reserve(transaction->getOutputCount());
  std::vector<uint32_t> globalIndexes;
  globalIndexes.reserve(transaction->getOutputCount());
  if (!transactionDetails.inBlockchain || !getTransactionGlobalIndexes(transactionDetails.hash, globalIndexes)) {
    for (size_t i = 0; i < transaction->getOutputCount(); ++i) {
      globalIndexes.push_back(0);
    }
  }

  assert(transaction->getOutputCount() == globalIndexes.size());
  for (size_t i = 0; i < transaction->getOutputCount(); ++i) {
    TransactionOutputDetails txOutDetails;
    txOutDetails.output = rawTransaction.outputs[i];
    txOutDetails.globalIndex = globalIndexes[i];
    transactionDetails.outputs.push_back(std::move(txOutDetails));
  }

  return transactionDetails;
}

std::vector<Crypto::Hash> Core::getAlternativeBlockHashesByIndex(uint32_t blockIndex) const {
  throwIfNotInitialized();

  std::vector<Crypto::Hash> alternativeBlockHashes;
  for (size_t chain = 1; chain < chainsLeaves.size(); ++chain) {
    IBlockchainCache* segment = chainsLeaves[chain];
    if (segment->getTopBlockIndex() < blockIndex) {
      continue;
    }

    do {
      if (segment->getTopBlockIndex() - segment->getBlockCount() + 1 <= blockIndex) {
        alternativeBlockHashes.push_back(segment->getBlockHash(blockIndex));
        break;
      } else if (segment->getTopBlockIndex() - segment->getBlockCount() - 1 > blockIndex) {
        segment = segment->getParent();
        assert(segment != nullptr);
      }
    } while (mainChainSet.count(segment) == 0);
  }
  return alternativeBlockHashes;
}

std::vector<Crypto::Hash> Core::getBlockHashesByTimestamps(uint64_t timestampBegin, size_t secondsCount) const {
  throwIfNotInitialized();

  logger(Logging::DEBUGGING) << "getBlockHashesByTimestamps request with timestamp "
                             << timestampBegin << " and seconds count " << secondsCount;

  auto mainChain = chainsLeaves[0];

  if (timestampBegin + static_cast<uint64_t>(secondsCount) < timestampBegin) {
    logger(Logging::WARNING) << "Timestamp overflow occured. Timestamp begin: " << timestampBegin
                             << ", timestamp end: " << (timestampBegin + static_cast<uint64_t>(secondsCount));

    throw std::runtime_error("Timestamp overflow");
  }

  return mainChain->getBlockHashesByTimestamps(timestampBegin, secondsCount);
}

std::vector<Crypto::Hash> Core::getTransactionHashesByPaymentId(const Hash& paymentId) const {
  throwIfNotInitialized();

  logger(Logging::DEBUGGING) << "getTransactionHashesByPaymentId request with paymentId " << paymentId;

  auto mainChain = chainsLeaves[0];

  std::vector<Crypto::Hash> hashes = mainChain->getTransactionHashesByPaymentId(paymentId);
  std::vector<Crypto::Hash> poolHashes = transactionPool->getTransactionHashesByPaymentId(paymentId);

  hashes.reserve(hashes.size() + poolHashes.size());
  std::move(poolHashes.begin(), poolHashes.end(), std::back_inserter(hashes));

  return hashes;
}

bool Core::getTransactionsByPaymentId(const Crypto::Hash& paymentId, std::vector<Transaction>& transactions) {
  auto blockchainTransactionHashes = getTransactionHashesByPaymentId(paymentId);
  auto poolTransactionHashes = transactionPool->getTransactionHashesByPaymentId(paymentId);

  std::vector<CachedTransaction> cachedTransactions;
  std::vector<Crypto::Hash> missedTransactions;
  std::vector<BinaryArray> rawTransactions;

  if (!poolTransactionHashes.empty()) {
    blockchainTransactionHashes.insert(blockchainTransactionHashes.end(), poolTransactionHashes.begin(), poolTransactionHashes.end());
  }

  if (blockchainTransactionHashes.empty()) {
    return false;
  }

  getTransactions(blockchainTransactionHashes, rawTransactions, missedTransactions);
  if (missedTransactions.size() > 0) {
    return false;
  }

	uint64_t cumulativeSize;

	if (!extractTransactions(rawTransactions,  cachedTransactions, cumulativeSize)) {
		return false;
	}

	for (const auto& CachedTransaction : cachedTransactions) {
		transactions.emplace_back(CachedTransaction.getTransaction());
	}

	return true;
}

Difficulty Core::getAvgDifficulty(uint32_t height, uint32_t window) const {
  throwIfNotInitialized();
  assert(height <= getTopBlockIndex());

  IBlockchainCache* mainChain = chainsLeaves[0];

  if (height == window) {
    return mainChain->getCurrentCumulativeDifficulty(height) / height;
  }

  std::vector<uint64_t> cumulDiffs = mainChain->getLastCumulativeDifficulties(window);
  return (cumulDiffs.back() - cumulDiffs.front()) / window;
}

uint64_t Core::getMinimalFee() {
  return getMinimalFeeForHeight(get_current_blockchain_height() - 1);
}

uint64_t Core::getMinimalFeeForHeight(uint32_t height) {
  IBlockchainCache* mainChain = chainsLeaves[0];
  uint32_t currentIndex = mainChain->getTopBlockIndex();

  if (height < 3 || currentIndex <= 1) {
    return 0;
  }

  if (height > currentIndex) {
    height = currentIndex;
  }

  uint32_t window = std::min(height, std::min<uint32_t>(currentIndex, static_cast<uint32_t>(CryptoNote::parameters::EXPECTED_NUMBER_OF_BLOCKS_PER_DAY)));
  if (window == 0) {
    ++window;
  }

  uint32_t offset = height - window;
  if (offset == 0) {
    ++offset;
  }

  // calculate average difficulty for ~last month
  std::vector<uint64_t> cumulDiffs = mainChain->getLastCumulativeDifficulties(window * 7 * 4 + 1); // Off-by-one bug in Karbo1 so we have to add here + 1 to get same value?
  uint64_t avgDifficultyCurrent = (cumulDiffs.back() - cumulDiffs.front()) / (window * 7 * 4);

  // historical reference moving average difficulty
  uint64_t avgDifficultyHistorical = mainChain->getCurrentCumulativeDifficulty(height) / height;

  /*
  * Total reward with transaction fees is used as the level of usage metric
  * to take into account transaction volume and cost of space in blockchain.
  */

  // calculate average reward for ~last day
  std::vector<uint64_t> rewards;
  rewards.reserve(window);
  for (; offset < height; offset++) {
    auto blockTemplate = getBlockByIndex(offset);
    rewards.push_back(get_outs_money_amount(blockTemplate.baseTransaction));
  }
  uint64_t avgRewardCurrent = std::accumulate(rewards.begin(), rewards.end(), 0ULL) / rewards.size();
  rewards.shrink_to_fit();

  // historical reference moving average reward
  uint64_t avgRewardHistorical = mainChain->getAlreadyGeneratedCoins(height) / height;

  return currency.getMinimalFee(avgDifficultyCurrent, avgRewardCurrent, avgDifficultyHistorical, avgRewardHistorical, height);
}

void Core::throwIfNotInitialized() const {
  if (!initialized) {
    throw std::system_error(make_error_code(error::CoreErrorCode::NOT_INITIALIZED));
  }
}

IBlockchainCache* Core::findSegmentContainingTransaction(const Crypto::Hash& transactionHash) const {
  assert(!chainsLeaves.empty());
  assert(!chainsStorage.empty());

  IBlockchainCache* segment = chainsLeaves[0];
  assert(segment != nullptr);

  //find in main chain
  do {
    if (segment->hasTransaction(transactionHash)) {
      return segment;
    }

    segment = segment->getParent();
  } while (segment != nullptr);

  //find in alternative chains
  for (size_t chain = 1; chain < chainsLeaves.size(); ++chain) {
    segment = chainsLeaves[chain];

    while (mainChainSet.count(segment) == 0) {
      if (segment->hasTransaction(transactionHash)) {
        return segment;
      }

      segment = segment->getParent();
    }
  }

  return nullptr;
}

bool Core::hasTransaction(const Crypto::Hash& transactionHash) const {
  throwIfNotInitialized();
  return findSegmentContainingTransaction(transactionHash) != nullptr || transactionPool->checkIfTransactionPresent(transactionHash);
}

void Core::transactionPoolCleaningProcedure() {
  System::Timer timer(dispatcher);

  try {
    for (;;) {
      timer.sleep(OUTDATED_TRANSACTION_POLLING_INTERVAL);

      auto deletedTransactions = transactionPool->clean();
      notifyObservers(makeDelTransactionMessage(std::move(deletedTransactions), Messages::DeleteTransaction::Reason::Outdated));
    }
  } catch (System::InterruptedException&) {
    logger(Logging::DEBUGGING) << "transactionPoolCleaningProcedure has been interrupted";
  } catch (std::exception& e) {
    logger(Logging::ERROR) << "Error occurred while cleaning transactions pool: " << e.what();
  }
}

void Core::updateBlockMedianSize() {
  auto mainChain = chainsLeaves[0];

  size_t nextBlockGrantedFullRewardZone = currency.blockGrantedFullRewardZoneByBlockVersion(upgradeManager->getBlockMajorVersion(mainChain->getTopBlockIndex() + 1));

  auto lastBlockSizes = mainChain->getLastBlocksSizes(currency.rewardBlocksWindow());

  blockMedianSize = std::max(Common::medianValue(lastBlockSizes), static_cast<uint64_t>(nextBlockGrantedFullRewardZone));
}

uint32_t Core::get_current_blockchain_height() const {
  return mainChainStorage->getBlockCount();
}

bool Core::isKeyImageSpent(const Crypto::KeyImage& key_im) {
  auto mainChain = chainsLeaves[0];
  return mainChain->checkIfSpent(key_im);
}

std::time_t Core::getStartTime() const {
  return start_time;
}

}
