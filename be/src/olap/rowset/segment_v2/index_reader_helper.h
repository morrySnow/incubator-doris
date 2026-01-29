// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

// NOTE: Simplified for hubspot branch - no ANN index support

#include "olap/rowset/segment_v2/index_iterator.h"
#include "olap/rowset/segment_v2/inverted_index_reader.h"

namespace doris::segment_v2 {
#include "common/compile_check_begin.h"

class IndexReaderHelper {
public:
    // NOTE: In hubspot branch, IndexReaderPtr is InvertedIndexReaderPtr
    // so all readers are inverted index readers
    static bool is_fulltext_index(const IndexReaderPtr& reader) {
        if (reader == nullptr) {
            return false;
        }
        return reader->type() == InvertedIndexReaderType::FULLTEXT;
    }

    static bool is_string_index(const IndexReaderPtr& reader) {
        if (reader == nullptr) {
            return false;
        }
        return reader->type() == InvertedIndexReaderType::STRING_TYPE;
    }

    static bool is_bkd_index(const IndexReaderPtr& reader) {
        if (reader == nullptr) {
            return false;
        }
        return reader->type() == InvertedIndexReaderType::BKD;
    }

    static bool is_support_phrase(const IndexReaderPtr& reader) {
        if (reader == nullptr) {
            return false;
        }
        const auto& properties = reader->get_index_properties();
        return get_parser_phrase_support_string_from_properties(properties) ==
               INVERTED_INDEX_PARSER_PHRASE_SUPPORT_YES;
    }

    // only string type or bkd index reader can be used for equal
    static bool has_string_or_bkd_index(const IndexIterator* iter) {
        if (iter == nullptr) {
            return false;
        }

        return iter->get_reader(InvertedIndexReaderType::STRING_TYPE) != nullptr ||
               iter->get_reader(InvertedIndexReaderType::BKD) != nullptr;
    }

    static bool has_bkd_index(const IndexIterator* iter) {
        if (iter == nullptr) {
            return false;
        }

        return iter->get_reader(InvertedIndexReaderType::BKD) != nullptr;
    }

    static bool has_string_index(const IndexIterator* iter) {
        if (iter == nullptr) {
            return false;
        }

        return iter->get_reader(InvertedIndexReaderType::STRING_TYPE) != nullptr;
    }

    // NOTE: Scoring not supported in hubspot branch - always returns false
    static bool is_need_similarity_score(InvertedIndexQueryType /*query_type*/,
                                         const TabletIndex* /*index_meta*/) {
        return false;
    }

    static bool is_need_similarity_score(TExprOpcode::type /*query_type*/,
                                         const TabletIndex* /*index_meta*/) {
        return false;
    }
};

#include "common/compile_check_end.h"
} // namespace doris::segment_v2
