#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96486);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/17 14:52:18 $");

  script_cve_id("CVE-2016-6664");
  script_bugtraq_id(93612);
  script_osvdb_id(
      149063,
      149065,
      149067,
      149068,
      149069,
      149351
  );

  script_name(english:"MariaDB 10.0.x < 10.0.29 Multiple Vulnerabilities");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.0.x prior to
10.0.29. It is, therefore, affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in
    scripts/mysqld_safe.sh due to improper handling of
    arguments to malloc-lib. A local attacker can exploit
    this, via a symlink attack on error logs, to gain root
    privileges. (CVE-2016-6664)

  - A denial of service vulnerability exists in the
    check_duplicate_key() function due to improper handling
    of error messages. An authenticated, remote attacker can
    exploit this to crash the database. (VulnDB 149063)

  - A denial of service vulnerability exists in the
    destroy() function in sql/sql_select.cc due to improper
    handling of a specially crafted query. An authenticated,
    remote attacker can exploit this to crash the database.
    (VulnDB 149065)

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
    safe_charset_converter() function in sql/item.cc due to
    improper handling of a specially crafted subselect query
    item. An authenticated, remote attacker can exploit this
    to crash the database. (VulnDB 149351)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10029-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10029-release-notes/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
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

mysql_check_version(variant:'MariaDB', fixed:'10.0.29-MariaDB', min:'10.0', severity:SECURITY_WARNING);
