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

#include "query_helper.h"

#include <algorithm>

namespace doris::segment_v2 {

// NOTE: Scoring/similarity functionality removed for hubspot branch
// Only is_simple_phrase is implemented

bool QueryHelper::is_simple_phrase(const std::vector<TermInfo>& term_infos) {
    return std::ranges::all_of(term_infos,
                               [](const auto& term_info) { return term_info.is_single_term(); });
}

} // namespace doris::segment_v2
