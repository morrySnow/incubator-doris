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

#include "olap/rowset/segment_v2/inverted_index/query_v2/all_query/all_query.h"

#include <gtest/gtest.h>

#include <memory>
#include <vector>

#include "olap/rowset/segment_v2/inverted_index/query_v2/query.h"
#include "olap/rowset/segment_v2/inverted_index/query_v2/scorer.h"

namespace doris::segment_v2::inverted_index::query_v2 {

class AllQueryTest : public testing::Test {
protected:
    std::vector<uint32_t> collect_docs(ScorerPtr scorer) {
        std::vector<uint32_t> result;
        uint32_t doc = scorer->doc();
        while (doc != TERMINATED) {
            result.push_back(doc);
            doc = scorer->advance();
        }
        return result;
    }
};

// Test AllQuery with max_doc from context
TEST_F(AllQueryTest, MaxDocFromContext) {
    const uint32_t max_doc = 100;
    AllQuery query;
    auto weight = query.weight();

    QueryExecutionContext ctx;
    ctx.segment_num_rows = max_doc;

    auto scorer = weight->scorer(ctx);
    auto docs = collect_docs(scorer);

    EXPECT_EQ(docs.size(), max_doc);
    for (uint32_t i = 0; i < max_doc; ++i) {
        EXPECT_EQ(docs[i], i);
    }
}

// Test AllQuery with deferred max_doc from context
TEST_F(AllQueryTest, DeferredMaxDocFromContext) {
    AllQuery query; // No max_doc parameter
    auto weight = query.weight();

    QueryExecutionContext ctx;
    ctx.segment_num_rows = 100;

    auto scorer = weight->scorer(ctx);
    auto docs = collect_docs(scorer);

    EXPECT_EQ(docs.size(), ctx.segment_num_rows);
    for (uint32_t i = 0; i < ctx.segment_num_rows; ++i) {
        EXPECT_EQ(docs[i], i);
    }
}

// Test AllQuery with zero segment_num_rows returns empty
TEST_F(AllQueryTest, ZeroSegmentNumRowsReturnsEmpty) {
    AllQuery query; // No max_doc parameter
    auto weight = query.weight();

    QueryExecutionContext ctx;
    ctx.segment_num_rows = 0;

    auto scorer = weight->scorer(ctx);
    EXPECT_EQ(scorer->doc(), TERMINATED);
}

// Test AllQuery with different context values
TEST_F(AllQueryTest, DifferentContextValues) {
    AllQuery query; // No max_doc parameter
    auto weight = query.weight();

    // First context with 50 rows
    QueryExecutionContext ctx1;
    ctx1.segment_num_rows = 50;
    auto scorer1 = weight->scorer(ctx1);
    auto docs1 = collect_docs(scorer1);
    EXPECT_EQ(docs1.size(), 50);

    // Second context with 200 rows (same weight, different context)
    QueryExecutionContext ctx2;
    ctx2.segment_num_rows = 200;
    auto scorer2 = weight->scorer(ctx2);
    auto docs2 = collect_docs(scorer2);
    EXPECT_EQ(docs2.size(), 200);
}

// Test AllScorer seek functionality
TEST_F(AllQueryTest, ScorerSeek) {
    AllQuery query;
    auto weight = query.weight();

    QueryExecutionContext ctx;
    ctx.segment_num_rows = 100;

    auto scorer = weight->scorer(ctx);

    // Seek to doc 50
    uint32_t doc = scorer->seek(50);
    EXPECT_EQ(doc, 50);

    // Seek to doc beyond max should return TERMINATED
    doc = scorer->seek(100);
    EXPECT_EQ(doc, TERMINATED);
}

// Test AllScorer size_hint
TEST_F(AllQueryTest, ScorerSizeHint) {
    AllQuery query;
    auto weight = query.weight();

    QueryExecutionContext ctx;
    ctx.segment_num_rows = 100;

    auto scorer = weight->scorer(ctx);
    EXPECT_EQ(scorer->size_hint(), 100);
}

} // namespace doris::segment_v2::inverted_index::query_v2
