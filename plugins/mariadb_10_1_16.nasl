#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93788);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_osvdb_id(
    141701,
    141702
  );

  script_name(english:"MariaDB 10.1.x < 10.1.16 Multiple DoS");
  script_summary(english:"Checks the MariaDB version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB running on the remote host is 10.1.x prior to
10.1.16. It is, therefore, affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists in the
    get_best_group_min_max() function within file
    sql/opt_range.cc when handling query plans. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 141701)

  - A denial of service vulnerability exists in the
    emb_stmt_execute() function within file
    libmysqld/lib_sql.cc when handling queries. An
    authenticated, remote attacker can exploit this to crash
    the database. (VulnDB 141702)");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.org/mariadb-10-1-16-now-available/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10116-changelog/");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb/mariadb-10116-release-notes/");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-10318");
  script_set_attribute(attribute:"see_also", value:"https://jira.mariadb.org/browse/MDEV-10324");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");

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

mysql_check_version(variant:'MariaDB', fixed:'10.1.16-MariaDB', min:'10.1', severity:SECURITY_WARNING);
