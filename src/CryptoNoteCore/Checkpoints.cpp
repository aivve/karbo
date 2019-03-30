// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2018, The TurtleCoin developers
// Copyright (c) 2018, The Karbo developers
//
// This file is part of Bytecoin.
//
// Bytecoin is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Bytecoin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Bytecoin.  If not, see <http://www.gnu.org/licenses/>.

#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <string>
#include <string.h>
#include <sstream>
#include <vector>
#include <iterator>
#include <boost/regex.hpp>

#include "Checkpoints.h"
#include "Common/StringTools.h"
#include "Common/DnsTools.h"

using namespace Logging;

namespace CryptoNote {
//---------------------------------------------------------------------------
Checkpoints::Checkpoints(Logging::ILogger &log) : logger(log, "checkpoints") {}
//---------------------------------------------------------------------------
bool Checkpoints::addCheckpoint(uint32_t index, const std::string &hash_str) {
  Crypto::Hash h = NULL_HASH;

  if (!Common::podFromHex(hash_str, h)) {
    logger(WARNING) << "Wrong hash in checkpoint for height " << index;
    return false;
  }

  if (!(0 == points.count(index))) {
    logger(WARNING) << "Checkpoint already exists for height" << index;
    return false;
  }

  points[index] = h;
  return true;
}
//---------------------------------------------------------------------------
bool Checkpoints::isInCheckpointZone(uint32_t index) const {
  return !points.empty() && (index <= (--points.end())->first);
}
//---------------------------------------------------------------------------
bool Checkpoints::checkBlock(uint32_t index, const Crypto::Hash &h,
                            bool& isCheckpoint) const {
  auto it = points.find(index);
  isCheckpoint = it != points.end();
  if (!isCheckpoint)
    return true;

  if (it->second == h) {
    logger(Logging::INFO, Logging::GREEN) 
      << "CHECKPOINT PASSED FOR INDEX " << index << " " << h;
    return true;
  } else {
    logger(Logging::WARNING, BRIGHT_YELLOW) << "CHECKPOINT FAILED FOR HEIGHT " << index
                                            << ". EXPECTED HASH: " << it->second
                                            << ", FETCHED HASH: " << h;
    return false;
  }
}
//---------------------------------------------------------------------------
bool Checkpoints::checkBlock(uint32_t index, const Crypto::Hash &h) const {
  bool ignored;
  return checkBlock(index, h, ignored);
}
//---------------------------------------------------------------------------
bool Checkpoints::isAlternativeBlockAllowed(uint32_t  blockchainSize,
                                            uint32_t  blockIndex) const {
  if (blockchainSize == 0) {
    return false;
  }

  auto it = points.upper_bound(blockchainSize);
  // Is blockchainSize before the first checkpoint?
  if (it == points.begin()) {
    return true;
  }

  --it;
  uint32_t checkpointIndex = it->first;
  return checkpointIndex < blockIndex;
}

std::vector<uint32_t> Checkpoints::getCheckpointHeights() const {
  std::vector<uint32_t> checkpointHeights;
  checkpointHeights.reserve(points.size());
  for (const auto& it : points) {
    checkpointHeights.push_back(it.first);
  }

  return checkpointHeights;
}
//---------------------------------------------------------------------------
const boost::regex linesregx("\\r\\n|\\n\\r|\\n|\\r");
const boost::regex fieldsregx(",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))");
bool Checkpoints::loadCheckpointsFromFile(const std::string& fileName) {
	std::string buff;
	if (!Common::loadFileToString(fileName, buff)) {
		logger(Logging::ERROR, BRIGHT_RED) << "Could not load checkpoints file: " << fileName;
		return false;
	}
	const char* data = buff.c_str();
	unsigned int length = strlen(data);

	boost::cregex_token_iterator li(data, data + length, linesregx, -1);
	boost::cregex_token_iterator end;

	int count = 0;
	while (li != end) {
		std::string line = li->str();
		++li;

		boost::sregex_token_iterator ti(line.begin(), line.end(), fieldsregx, -1);
		boost::sregex_token_iterator end2;

		std::vector<std::string> row;
		while (ti != end2) {
			std::string token = ti->str();
			++ti;
			row.push_back(token);
		}
		if (row.size() != 2) {
			logger(Logging::ERROR, BRIGHT_RED) << "Invalid checkpoint file format";
			return false;
		}
		else {
			uint32_t height = stoi(row[0]);
			bool r = addCheckpoint(height, row[1]);
			if (!r) {
				return false;
			}
			count += 1;
		}
	}
	logger(Logging::INFO) << "Loaded " << count << " checkpoint(s) from " << fileName;
	return true;
}
//---------------------------------------------------------------------------
#ifndef __ANDROID__
bool Checkpoints::loadCheckpointsFromDns()
{
  std::string domain("checkpoints.karbo.org");
  std::vector<std::string>records;

  if (!Common::fetch_dns_txt(domain, records)) {
    logger(Logging::INFO) << "Failed to lookup DNS checkpoint records from " << domain;
  }

  for (const auto& record : records) {
	  uint32_t height;
	  Crypto::Hash hash = NULL_HASH;
	  std::stringstream ss;

	  int del = record.find_first_of(':');
	  std::string height_str = record.substr(0, del), hash_str = record.substr(del + 1, 64);
	  ss = std::stringstream(height_str);
      ss >> height;
	  char c;
	  if ((ss.fail() || ss.get(c)) || !Common::podFromHex(hash_str, hash)) {
		  logger(Logging::INFO) << "Failed to parse DNS checkpoint record: " << record;
		  continue;
	  }

	  if (!(0 == points.count(height))) {
		  logger(DEBUGGING) << "Checkpoint already exists for height: " << height << ". Ignoring DNS checkpoint.";
	  }
	  else {
		  addCheckpoint(height, hash_str);
	  }
  }

  return true;
}
#endif
