#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93829);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id(
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0649",
    "CVE-2016-0650",
    "CVE-2016-0668"
  );
  script_osvdb_id(
    134561,
    134562,
    134563,
    135238,
    135240,
    135275,
    135276,
    135277,
    137324,
    137325,
    137326,
    137337,
    137339,
    137342,
    137348
  );

  script_name(english:"MariaDB 10.1.x < 10.1.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.12. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to impact
    integrity and availability. (CVE-2016-0640)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows an authenticated, remote attacker to
    disclose sensitive information or cause a denial of
    service condition. (CVE-2016-0641)

  - An unspecified flaw exists in the DDL subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0644)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0646)

  - An unspecified flaw exists in the PS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0649)

  - An unspecified flaw exists in the Replication
    subcomponent that allows an authenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2016-0650)

  - An unspecified flaw exists in the InnoDB subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-0668)

  - A denial of service vulnerability exists in the
    SELECT_LEX::update_used_tables() function in sql_lex.cc
    due to improper handling of semi-join conditions on used
    table updates. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 134561)

  - A denial of service vulnerability exists in the
    JOIN::choose_subquery_plan() function in
    opt_subselect.cc due to improper handling of nested IN
    clauses that contain SQ. An authenticated, remote
    attacker can exploit this to crash the database.
    (VulnDB 134562)

  - A denial of service vulnerability exists in the
    select_create::prepare() function in sql_insert.cc due
    to improper handling of stored procedures in new tables.
    An authenticated, remote attacker can exploit this to
    crash the database. (VulnDB 134563)

  - A denial of service vulnerability exists in
    item_cmpfunc.cc due to improper handling of EXECUTE
    statements. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 135238)

  - A denial of service vulnerability exists in the
    subselect_hash_sj_engine::exec() function in
    item_subselect.cc due to improper handling of UNION ALL
    statements. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 135240)

  - A denial of service vulnerability exists in the
    Rows_log_event::process_triggers() function in
    log_event.cc due to improper handling of the update
    statement for minimal row image sets. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 135275)

  - A denial of service vulnerability exists in
    sql_select.cc due to improper creation of keys in
    temporary tables. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 135277)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://mariadb.org/mariadb-10-1-12-and-mariadb-galera-cluster-10-0-24-5-5-48-now-available/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2747217e");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10112-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10112-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'10.1.12-MariaDB', min:'10.1', severity:SECURITY_WARNING);
