#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64935);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/09/28 21:23:45 $");

  script_cve_id(
    "CVE-2012-0572",
    "CVE-2012-0574",
    "CVE-2012-0578",
    "CVE-2012-1702",
    "CVE-2012-1705",
    "CVE-2012-5096",
    "CVE-2012-5611",
    "CVE-2012-5612",
    "CVE-2012-5615",
    "CVE-2012-5627",
    "CVE-2013-0367",
    "CVE-2013-0368",
    "CVE-2013-0371",
    "CVE-2013-0375",
    "CVE-2013-0383",
    "CVE-2013-0384",
    "CVE-2013-0385",
    "CVE-2013-0386",
    "CVE-2013-0389"
  );
  script_bugtraq_id(
    56766,
    56768,
    56769,
    56837,
    57334,
    57385,
    57388,
    57391,
    57397,
    57400,
    57405,
    57408,
    57410,
    57412,
    57414,
    57415,
    57416,
    57417,
    57418
  );
  script_osvdb_id(
    88060,
    88064,
    88066,
    88067,
    88415,
    89251,
    89252,
    89253,
    89254,
    89255,
    89256,
    89257,
    89258,
    89259,
    89260,
    89261,
    89262,
    89263,
    89264,
    89265
  );
  script_xref(name:"EDB-ID", value:"23075");
  script_xref(name:"EDB-ID", value:"23076");

  script_name(english:"MariaDB 5.5 < 5.5.29 Multiple Vulnerabilities");
  script_summary(english:"Checks MariaDB version");

  script_set_attribute(attribute:"synopsis", value:"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB 5.5 running on the remote host is prior to
5.5.29. It is, therefore, potentially affected by vulnerabilities
in the following components :

  - Information Schema
  - InnoDB
  - MyISAM
  - Server
  - Server Locking
  - Server Optimizer
  - Server Parser
  - Server Partition
  - Server Privileges
  - Server Replication
  - Stored Procedure");
  script_set_attribute(attribute:"see_also", value:"https://kb.askmonty.org/en/mariadb-5529-release-notes/");
  # MariaDB 5.5.29 includes MySQL 5.5.29
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.5/en/news-5-5-29.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MariaDB 5.5.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(variant:'MariaDB', fixed:'5.5.29-MariaDB', min:'5.5', severity:SECURITY_HOLE);
