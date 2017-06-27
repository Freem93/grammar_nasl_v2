#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93845);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id(
    "CVE-2015-4816",
    "CVE-2015-4819",
    "CVE-2015-4879",
    "CVE-2015-4895"
  );
  script_bugtraq_id(
    77134,
    77136,
    77140,
    77196
  );
  script_osvdb_id(
    129164,
    129171,
    129180,
    129190,
    125894,
    125895,
    125896,
    125897,
    125904
  );

  script_name(english:"MariaDB 10.0.x < 10.0.21 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is 10.0.x prior
to 10.0.21. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified flaws exist in the InnoDB component
    that allow an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2015-4816,
    CVE-2015-4895)

  - An unspecified flaw exists in the Client Programs
    component that allows a local attacker to gain elevated
    privileges. (CVE-2015-4819)

  - An unspecified flaw exists in the DML subcomponent that
    allows an authenticated, remote attacker to impact
    confidentiality, integrity, and availability. No other
    details are available. (CVE-2015-4879)

  - A denial of service vulnerability exists in the
    base_list_iterator::next_fast() function within file
    sql/sql_parse.cc when handling multi-table updates. An
    authenticated, remote attacker can exploit this to crash
    the server. (VulnDB 125894)

  - A denial of service vulnerability exists in the
    ACL_internal_schema_registry::lookup() function within
    file sql/sql_acl.cc when handling multi-table updates.
    An authenticated, remote attacker can exploit this to
    crash the server. (VulnDB 125895)

  - A denial of service vulnerability exists in the
    Item_func_group_concat::fix_fields() function within
    file sql/item_sum.cc when handling arguments on the
    second execution of PS. An authenticated, remote
    attacker can exploit this to crash the server.
    (VulnDB 125896)

  - A denial of service vulnerability exists in
    select_lex->non_agg_fields when using ONLY_FULL_GROUP_BY
    in a stored procedure or trigger that is repeatedly
    executed. An authenticated, remote attacker can exploit
    this to crash the server. (VulnDB 125897)

  - A denial of service vulnerability exists in the
    Materialized_cursor() function within file
    sql/sql_cursor.cc when handling temporary tables. An
    authenticated, remote attacker can exploit this to crash
    the server. (VulnDB 125904)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10021-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10021-changelog/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

mysql_check_version(variant:'MariaDB', fixed:'10.0.21-MariaDB', min:'10.0', severity:SECURITY_HOLE);
