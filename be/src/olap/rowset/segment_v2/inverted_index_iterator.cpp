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

#include "inverted_index_iterator.h"

#include <memory>

#include "common/cast_set.h"
#include "olap/rowset/segment_v2/inverted_index_cache.h"
#include "olap/rowset/segment_v2/inverted_index_reader.h"

namespace doris::segment_v2 {

// New interface constructor
InvertedIndexIterator::InvertedIndexIterator() {}

// Old interface constructor (backward compatibility)
InvertedIndexIterator::InvertedIndexIterator(const io::IOContext& io_ctx,
                                             OlapReaderStatistics* stats,
                                             RuntimeState* runtime_state)
        : _io_ctx(io_ctx), _stats(stats), _runtime_state(runtime_state) {}

void InvertedIndexIterator::add_reader(InvertedIndexReaderType type,
                                       const InvertedIndexReaderPtr& reader) {
    _readers[type] = reader;
}

// New interface implementation (cherry-picked code)
Status InvertedIndexIterator::read_from_index(const IndexParam& param) {
    auto* i_param = std::get<InvertedIndexParam*>(param);
    if (i_param == nullptr) {
        return Status::Error<ErrorCode::INVERTED_INDEX_NOT_SUPPORTED>("i_param is null");
    }
    DBUG_EXECUTE_IF("return_inverted_index_bypass", {
        return Status::Error<ErrorCode::INVERTED_INDEX_BYPASS>("inverted index bypass");
    });

    auto reader = DORIS_TRY(select_best_reader(i_param->column_type, i_param->query_type));
    if (UNLIKELY(reader == nullptr)) {
        throw CLuceneError(CL_ERR_NullPointer, "bkd index reader is null", false);
    }

    RuntimeState* runtime_state = _context ? _context->runtime_state : _runtime_state;
    OlapReaderStatistics* stats = _context ? _context->stats : _stats;
    const io::IOContext* io_ctx = _context ? _context->io_ctx : &_io_ctx;

    if (!i_param->skip_try && reader->type() == InvertedIndexReaderType::BKD) {
        if (runtime_state != nullptr &&
            runtime_state->query_options().inverted_index_skip_threshold > 0 &&
            runtime_state->query_options().inverted_index_skip_threshold < 100) {
            auto query_bkd_limit_percent =
                    runtime_state->query_options().inverted_index_skip_threshold;
            uint32_t hit_count = 0;
            RETURN_IF_ERROR(try_read_from_inverted_index(reader, i_param->column_name,
                                                         i_param->query_value, i_param->query_type,
                                                         &hit_count));
            if (hit_count > i_param->num_rows * query_bkd_limit_percent / 100) {
                return Status::Error<ErrorCode::INVERTED_INDEX_BYPASS>(
                        "hit count: {}, bkd inverted reached limit {}% , segment num "
                        "rows:{}", // add blackspace after % to avoid log4j format bug
                        hit_count, query_bkd_limit_percent, i_param->num_rows);
            }
        }
    }

    auto execute_query = [&]() {
        return reader->query(io_ctx, stats, runtime_state, i_param->column_name,
                             i_param->query_value, i_param->query_type, i_param->roaring);
    };

    if (runtime_state->query_options().enable_profile) {
        InvertedIndexQueryStatistics query_stats;
        {
            SCOPED_RAW_TIMER(&query_stats.exec_time);
            RETURN_IF_ERROR(execute_query());
        }
        query_stats.column_name = i_param->column_name;
        query_stats.hit_rows = i_param->roaring->cardinality();
        stats->inverted_index_stats.stats.emplace_back(query_stats);
    } else {
        RETURN_IF_ERROR(execute_query());
    }

    return Status::OK();
}

// Old interface implementation (backward compatibility)
Status InvertedIndexIterator::read_from_inverted_index(
        const vectorized::IndexFieldNameAndTypePair& name_with_type, const void* query_value,
        InvertedIndexQueryType query_type, uint32_t segment_num_rows,
        std::shared_ptr<roaring::Roaring>& bit_map, bool skip_try) {
    DBUG_EXECUTE_IF("return_inverted_index_bypass", {
        return Status::Error<ErrorCode::INVERTED_INDEX_BYPASS>("inverted index bypass");
    });
    auto reader = DORIS_TRY(_select_best_reader(name_with_type.second, query_type));
    if (UNLIKELY(reader == nullptr)) {
        throw CLuceneError(CL_ERR_NullPointer, "bkd index reader is null", false);
    }
    if (!skip_try && reader->type() == InvertedIndexReaderType::BKD) {
        if (_runtime_state != nullptr &&
            _runtime_state->query_options().inverted_index_skip_threshold > 0 &&
            _runtime_state->query_options().inverted_index_skip_threshold < 100) {
            auto query_bkd_limit_percent =
                    _runtime_state->query_options().inverted_index_skip_threshold;
            uint32_t hit_count = 0;
            RETURN_IF_ERROR(try_read_from_inverted_index(reader, name_with_type.first, query_value,
                                                         query_type, &hit_count));
            if (hit_count > segment_num_rows * query_bkd_limit_percent / 100) {
                return Status::Error<ErrorCode::INVERTED_INDEX_BYPASS>(
                        "hit count: {}, bkd inverted reached limit {}%, segment num rows:{}",
                        hit_count, query_bkd_limit_percent, segment_num_rows);
            }
        }
    }

    auto execute_query = [&]() {
        return reader->query(&_io_ctx, _stats, _runtime_state, name_with_type.first, query_value,
                             query_type, bit_map);
    };

    if (_runtime_state->query_options().enable_profile) {
        InvertedIndexQueryStatistics query_stats;
        {
            SCOPED_RAW_TIMER(&query_stats.exec_time);
            RETURN_IF_ERROR(execute_query());
        }
        query_stats.column_name = name_with_type.first;
        query_stats.hit_rows = bit_map->cardinality();
        _stats->inverted_index_stats.stats.emplace_back(query_stats);
    } else {
        RETURN_IF_ERROR(execute_query());
    }

    return Status::OK();
}

// Old interface (backward compatibility)
Status InvertedIndexIterator::try_read_from_inverted_index(const InvertedIndexReaderPtr& reader,
                                                           const std::string& column_name,
                                                           const void* query_value,
                                                           InvertedIndexQueryType query_type,
                                                           uint32_t* count) {
    // NOTE: only bkd index support try read now.
    if (query_type == InvertedIndexQueryType::GREATER_EQUAL_QUERY ||
        query_type == InvertedIndexQueryType::GREATER_THAN_QUERY ||
        query_type == InvertedIndexQueryType::LESS_EQUAL_QUERY ||
        query_type == InvertedIndexQueryType::LESS_THAN_QUERY ||
        query_type == InvertedIndexQueryType::EQUAL_QUERY) {
        RETURN_IF_ERROR(
                reader->try_query(&_io_ctx, _stats, column_name, query_value, query_type, count));
    }
    return Status::OK();
}

// New interface helper (size_t version)
Status InvertedIndexIterator::try_read_from_inverted_index(const InvertedIndexReaderPtr& reader,
                                                           const std::string& column_name,
                                                           const void* query_value,
                                                           InvertedIndexQueryType query_type,
                                                           size_t* count) {
    uint32_t count32 = 0;
    auto status = try_read_from_inverted_index(reader, column_name, query_value, query_type, &count32);
    *count = count32;
    return status;
}

// Old interface (backward compatibility)
Status InvertedIndexIterator::read_null_bitmap(InvertedIndexQueryCacheHandle* cache_handle,
                                               lucene::store::Directory* dir) {
    auto reader = DORIS_TRY(_select_best_reader());
    return reader->read_null_bitmap(&_io_ctx, _stats, cache_handle, dir);
}

// New interface override
Status InvertedIndexIterator::read_null_bitmap(InvertedIndexQueryCacheHandle* cache_handle) {
    auto reader = DORIS_TRY(select_best_reader());
    const io::IOContext* io_ctx = _context ? _context->io_ctx : &_io_ctx;
    OlapReaderStatistics* stats = _context ? _context->stats : _stats;
    return reader->read_null_bitmap(io_ctx, stats, cache_handle, nullptr);
}

Result<bool> InvertedIndexIterator::has_null() {
    auto reader = DORIS_TRY(_select_best_reader());
    return reader->has_null();
}

Result<InvertedIndexReaderPtr> InvertedIndexIterator::select_best_reader(
        const vectorized::DataTypePtr& column_type, InvertedIndexQueryType query_type) {
    return _select_best_reader(column_type, query_type);
}

Result<InvertedIndexReaderPtr> InvertedIndexIterator::select_best_reader() {
    return _select_best_reader();
}

Result<InvertedIndexReaderPtr> InvertedIndexIterator::_select_best_reader(
        const vectorized::DataTypePtr& column_type, InvertedIndexQueryType query_type) {
    if (_readers.empty()) {
        return ResultError(Status::RuntimeError(
                "No available inverted index readers. Check if index is properly initialized."));
    }

    // BKD and array types allow only one reader each
    if (_readers.size() == 1) {
        return _readers.begin()->second;
    }

    // Check for string types
    const auto field_type = column_type->get_storage_field_type();
    const bool is_string = is_string_type(field_type);

    InvertedIndexReaderType preferred_type = InvertedIndexReaderType::UNKNOWN;
    // Handle string type columns
    if (is_string) {
        if (is_match_query(query_type)) {
            preferred_type = InvertedIndexReaderType::FULLTEXT;
        } else if (is_equal_query(query_type)) {
            preferred_type = InvertedIndexReaderType::STRING_TYPE;
        }
    }
    DBUG_EXECUTE_IF("inverted_index_reader.select_best_reader", {
        auto type = DebugPoints::instance()->get_debug_param_or_default<int32_t>(
                "inverted_index_reader.select_best_reader", "type", -1);
        if ((int32_t)preferred_type != type) {
            return ResultError(Status::RuntimeError(
                    "Inverted index reader type mismatch. Expected={}, Actual={}",
                    (int32_t)preferred_type, type));
        }
    })

    if (auto reader = get_reader(preferred_type)) {
        return std::static_pointer_cast<InvertedIndexReader>(reader);
    }

    return ResultError(Status::RuntimeError("Index query type not supported"));
}

Result<InvertedIndexReaderPtr> InvertedIndexIterator::_select_best_reader() {
    if (_readers.empty()) {
        return ResultError(Status::RuntimeError(
                "No available inverted index readers. Check if index is properly initialized."));
    }
    return _readers.begin()->second;
}

// New interface - returns IndexReaderPtr
IndexReaderPtr InvertedIndexIterator::get_reader(IndexReaderType reader_type) const {
    auto iter = _readers.find(reader_type);
    if (iter == _readers.end()) {
        return nullptr;
    }
    return iter->second;
}

// Old interface - returns InvertedIndexReaderPtr
InvertedIndexReaderPtr InvertedIndexIterator::get_reader(InvertedIndexReaderType type) {
    auto iter = _readers.find(type);
    if (iter == _readers.end()) {
        return nullptr;
    }
    return iter->second;
}

} // namespace doris::segment_v2
