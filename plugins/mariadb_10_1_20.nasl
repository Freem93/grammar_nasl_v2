#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96487);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/17 14:52:18 $");

  script_osvdb_id(
      149062,
      149063,
      149064,
      149065,
      149066,
      149067,
      149068,
      149069,
      149070,
      149071,
      149350,
      149351
  );

  script_name(english:"MariaDB 10.1.x < 10.1.20 Multiple DoS");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.20. It is, therefore, affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists in the
    trx_state_eq() function due to improper handling of
    state errors. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149062)

  - A denial of service vulnerability exists in the
    check_duplicate_key() function due to improper handling
    of error messages. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149063)

  - A denial of service vulnerability exists in the
    lock_rec_queue_validate() function in lock/lock0lock.cc
    due to improper handling of lock requests. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149064)

  - A denial of service vulnerability exists in the
    destroy() function in sql/sql_select.cc due to improper
    handling of a specially crafted query. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149065)

  - A denial of service vulnerability exists in the
    calculate_cond_selectivity_for_table() function in
    sql/opt_range.cc due to improper handling of
    'thd->no_errors'. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149066)

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

  - A denial of service vulnerability exists in
    sql/statistics.cc due o improper handling of stat
    tables. An authenticated, remote attacker can exploit
    this to crash the database. (VulnDB 149070)

  - A denial of service vulnerability exists in the
    parse_filter_rule() function in sql/rpl_filter.cc 
    that is triggered during the clearing of wildcards. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 149071)

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
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10120-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10120-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/18");
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

mysql_check_version(variant:'MariaDB', fixed:'10.1.20-MariaDB', min:'10.1', severity:SECURITY_WARNING);
