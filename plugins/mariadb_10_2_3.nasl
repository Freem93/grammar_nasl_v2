#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96488);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/17 14:52:18 $");

  script_osvdb_id(
      149062,
      149064,
      149067,
      149068,
      149069,
      149337,
      149338,
      149339,
      149340,
      149341,
      149342,
      149343,
      149344,
      149345,
      149346,
      149347,
      149348,
      149349,
      149350,
      149351
  );

  script_name(english:"MariaDB 10.2.x < 10.2.3 Multiple DoS");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.2.x prior to
10.2.3. It is, therefore, affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists in the
    trx_state_eq() function due to improper handling of
    state errors. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149062)

  - A denial of service vulnerability exists in the
    lock_rec_queue_validate() function in lock/lock0lock.cc
    due to improper handling of lock requests. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149064)

  - A denial of service vulnerability exists in the
    date_add_interval() function in sql/sql_time.cc due to
    improper handling of INTERVAL arguments. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149067)

  - A denial of service vulnerability exists in
    sql/item_subselect.cc due to improper handling of
    queries from the select/unit tree. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149068)

  - A denial of service vulnerability exists in the
    check_well_formed_result() function in sql/item.cc due
    to improper handling of row validation. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149069)

  - A denial of service vulnerability exists in the
    check_contains() function in sql/item_jsonfunc.cc due to
    improper handling of a specially crafted array. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149337)

  - A denial of service vulnerability exists in the
    init_ror_merged_scan() function in sql/opt_range.cc due
    to improper handling a specially crafted table column.
    An authenticated, remote attacker can exploit this to
    crash the database. (VulnDB 149338)

  - A denial of service vulnerability exists in the
    val_str() function in sql/item_jsonfunc.cc due to
    improper handling of scalar values. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149339)

  - A denial of service vulnerability exists in the
    mark_object() and mark_array() functions in
    strings/json_lib.c due to improper handling of
    JSON_VALID selections. An authenticated, remote attacker
    can exploit this to crash the database. (VulnDB 149340)

  - A denial of service vulnerability exists in the
    mark_object() and mark_array() functions in
    strings/json_lib.c due to improper handling of
    JSON arrays. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149341)

  - A denial of service vulnerability exists in the
    mark_object() and mark_array() functions in
    strings/json_lib.c due to improper handling of
    JSON_VALID selections. An authenticated, remote attacker
    can exploit this to crash the database. (VulnDB 149342)

  - A denial of service vulnerability exists in the
    fix_length_and_dec() function in sql/item_jsonfunc.cc
    due to improper handling of JSON casting. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149343)

  - A denial of service vulnerability exists in the
    fparse_one_or_all() function in sql/item_jsonfunc.cc due
    to improper handling of input passed via the
    'one_or_all' parameter. An authenticated, remote
    attacker can exploit this to crash the database.
    (VulnDB 149344)

  - A denial of service vulnerability exists in the
    val_str() function in sql/item_jsonfunc.cc due to
    improper handling of value_length. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149345)

  - A denial of service vulnerability exists in the
    val_int() function in sql/item_jsonfunc.cc due to
    improper handling of NULL paths. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149346)

  - A denial of service vulnerability exists in the
    merge_buffers() function in sql/filesort.cc due to
    improper handling of sort_union optimization. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149347)

  - A denial of service vulnerability exists in the
    mysql_rm_table_no_locks() function in sql/sql_table.cc
    that is triggered when dropping temporary tables. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149348)

  - A denial of service vulnerability exists in the
    check_view_single_update() function in sql/sql_insert.cc
    that is triggered when inserting specially crafted
    tables. An authenticated, remote attacker can exploit
    this to crash the database. (VulnDB 149349)

  - A denial of service vulnerability exists in the
    lock_reset_lock_and_trx_wait() function in
    storage/innobase/lock/lock0lock.cc due to improper
    handling of NULL values in wait_lock. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149350)

  - A denial of service vulnerability exists in the
    safe_charset_converter() function in sql/item.cc due to
    improper handling of a specially crafted subselect query
    item. An authenticated, remote attacker can exploit this
    to crash the database. (VulnDB 149351)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-1023-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-1023-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.2.3-MariaDB', min:'10.2', severity:SECURITY_WARNING);
