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

#include "olap/rowset/segment_v2/inverted_index/query_v2/score_combiner.h"

#include <gtest/gtest.h>

#include <memory>

#include "olap/rowset/segment_v2/inverted_index/query_v2/scorer.h"

namespace doris {

using segment_v2::inverted_index::query_v2::DoNothingCombiner;
using segment_v2::inverted_index::query_v2::DoNothingCombinerPtr;
using segment_v2::inverted_index::query_v2::Scorer;
using segment_v2::inverted_index::query_v2::ScorerPtr;

class ConstScorer final : public Scorer {
public:
    explicit ConstScorer(float v) : _v(v) {}
    ~ConstScorer() override = default;

    float score() override { return _v; }

private:
    float _v;
};

class ScoreCombinerTest : public ::testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ScoreCombinerTest, DoNothingCombinerBehavior) {
    DoNothingCombiner comb;
    EXPECT_FLOAT_EQ(comb.score(), 0.0F);

    comb.update(std::make_shared<ConstScorer>(10.0F));
    EXPECT_FLOAT_EQ(comb.score(), 0.0F);

    comb.clear();
    EXPECT_FLOAT_EQ(comb.score(), 0.0F);

    DoNothingCombinerPtr cloned = comb.clone();
    ASSERT_TRUE(cloned != nullptr);
    EXPECT_FLOAT_EQ(cloned->score(), 0.0F);

    cloned->update(std::make_shared<ConstScorer>(3.14F));
    EXPECT_FLOAT_EQ(cloned->score(), 0.0F);
}

} // namespace doris
