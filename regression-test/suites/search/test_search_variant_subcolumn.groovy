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

/**
 * Test search() function with variant column and inverted index.
 *
 * This test covers the following scenarios:
 * 1. Variant column with limited subcolumns count (variant_max_subcolumns_count)
 * 2. Mixed data types in the same variant subcolumn
 * 3. Search on non-existent variant subcolumns
 * 4. Search on variant subcolumns that may not have indexes built
 *
 * Related issue: Variant 列倒排索引 search 查询报错：No segments file found
 */
suite("test_search_variant_subcolumn") {
    def tableName = "test_variant_search_subcolumn_issue"

    sql "DROP TABLE IF EXISTS ${tableName}"

    // Test Case 1: Variant with limited subcolumns count
    // This reproduces the issue where variant_max_subcolumns_count limits
    // which subcolumns get materialized and indexed
    sql """
        CREATE TABLE ${tableName} (
            a INT NOT NULL,
            ch VARIANT<PROPERTIES("variant_max_subcolumns_count" = "2")> NULL,
            INDEX idx_ch (ch) USING INVERTED PROPERTIES(
                "lower_case" = "true",
                "parser" = "unicode",
                "support_phrase" = "true"
            )
        ) ENGINE=OLAP
        UNIQUE KEY(a)
        DISTRIBUTED BY HASH(a) BUCKETS 1
        PROPERTIES (
            "replication_allocation" = "tag.location.default: 1",
            "disable_auto_compaction" = "true"
        )
    """

    // Insert test data with mixed types in the same subcolumn
    sql """INSERT INTO ${tableName} VALUES(1, '{"a": "abc def"}')"""
    sql """INSERT INTO ${tableName} VALUES(2, '{"a": 1}')"""
    sql """INSERT INTO ${tableName} VALUES(3, '{"a": "abc def"}')"""

    // Wait for data to be flushed
    Thread.sleep(5000)

    // Test 1: Search on non-existent subcolumn should return 0 rows (not error)
    qt_search_nonexistent """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ * FROM ${tableName}
        WHERE search('ch.b:abc', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 2: Search on existing subcolumn with string values
    qt_search_existing """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:abc', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 3: Search with AND operator on same subcolumn
    qt_search_and """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:abc AND ch.a:def', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 4: Search with phrase on variant subcolumn
    qt_search_phrase """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:"abc def"', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Clean up and test with unlimited subcolumns
    sql "DROP TABLE IF EXISTS ${tableName}"

    // Test Case 2: Variant with unlimited subcolumns (variant_max_subcolumns_count = 0)
    sql """
        CREATE TABLE ${tableName} (
            a INT NOT NULL,
            ch VARIANT<PROPERTIES("variant_max_subcolumns_count" = "0")> NULL,
            INDEX idx_ch (ch) USING INVERTED PROPERTIES(
                "lower_case" = "true",
                "parser" = "unicode",
                "support_phrase" = "true"
            )
        ) ENGINE=OLAP
        UNIQUE KEY(a)
        DISTRIBUTED BY HASH(a) BUCKETS 1
        PROPERTIES (
            "replication_allocation" = "tag.location.default: 1",
            "disable_auto_compaction" = "true"
        )
    """

    // Insert same test data
    sql """INSERT INTO ${tableName} VALUES(1, '{"a": "abc def", "b": "xyz"}')"""
    sql """INSERT INTO ${tableName} VALUES(2, '{"a": 1, "b": "test value"}')"""
    sql """INSERT INTO ${tableName} VALUES(3, '{"a": "abc def", "c": "other"}')"""

    Thread.sleep(5000)

    // Test 5: Search on subcolumn with unlimited sparse columns
    qt_search_sparse_a """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:abc', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 6: Search on another subcolumn
    qt_search_sparse_b """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.b:test', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 7: Search on non-existent subcolumn in sparse mode
    qt_search_sparse_nonexistent """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ COUNT(*) FROM ${tableName}
        WHERE search('ch.nonexistent:value', '{"mode":"lucene"}')
    """

    // Test 8: OR search across multiple variant subcolumns
    qt_search_or """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:abc OR ch.b:test', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Test 9: Complex query mixing existing and non-existing subcolumns
    qt_search_complex """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ a FROM ${tableName}
        WHERE search('ch.a:abc OR ch.nonexistent:value', '{"mode":"lucene"}')
        ORDER BY a
    """

    // Clean up
    sql "DROP TABLE IF EXISTS ${tableName}"

    // Test Case 3: Variant with nested subcolumns
    sql """
        CREATE TABLE ${tableName} (
            id INT NOT NULL,
            data VARIANT<PROPERTIES("variant_max_subcolumns_count" = "0")> NULL,
            INDEX idx_data (data) USING INVERTED PROPERTIES(
                "lower_case" = "true",
                "parser" = "unicode",
                "support_phrase" = "true"
            )
        ) ENGINE=OLAP
        DUPLICATE KEY(id)
        DISTRIBUTED BY HASH(id) BUCKETS 1
        PROPERTIES (
            "replication_allocation" = "tag.location.default: 1",
            "disable_auto_compaction" = "true"
        )
    """

    sql """INSERT INTO ${tableName} VALUES(1, '{"user": {"name": "alice smith", "email": "alice@example.com"}}')"""
    sql """INSERT INTO ${tableName} VALUES(2, '{"user": {"name": "bob jones", "email": "bob@example.com"}}')"""
    sql """INSERT INTO ${tableName} VALUES(3, '{"user": {"name": "charlie smith", "city": "new york"}}')"""

    Thread.sleep(5000)

    // Test 10: Search on nested variant path
    qt_search_nested """
        SELECT /*+SET_VAR(enable_common_expr_pushdown=true)*/ id FROM ${tableName}
        WHERE search('data.user.name:smith', '{"mode":"lucene"}')
        ORDER BY id
    """

    sql "DROP TABLE IF EXISTS ${tableName}"

    logger.info("All variant subcolumn search tests completed!")
}
