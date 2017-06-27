#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66178);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/07/24 14:56:42 $");

  script_cve_id(
    "CVE-2012-5614",
    "CVE-2013-1502",
    "CVE-2013-1506",
    "CVE-2013-1511",
    "CVE-2013-1512",
    "CVE-2013-1521",
    "CVE-2013-1523",
    "CVE-2013-1526",
    "CVE-2013-1531",
    "CVE-2013-1532",
    "CVE-2013-1544",
    "CVE-2013-1552",
    "CVE-2013-1555",
    "CVE-2013-2375",
    "CVE-2013-2376",
    "CVE-2013-2378",
    "CVE-2013-2389",
    "CVE-2013-2391",
    "CVE-2013-2392",
    "CVE-2013-3794",
    "CVE-2013-3801",
    "CVE-2013-3805",
    "CVE-2013-3808"
  );
  script_bugtraq_id(
    56776,
    59180,
    59188,
    59196,
    59201,
    59202,
    59207,
    59209,
    59210,
    59211,
    59217,
    59218,
    59224,
    59225,
    59227,
    59229,
    59237,
    59239,
    59242,
    61222,
    61227,
    61256,
    61269
  );
  script_osvdb_id(
    88065,
    92463,
    92464,
    92465,
    92466,
    92467,
    92469,
    92470,
    92471,
    92472,
    92473,
    92474,
    92475,
    92476,
    92477,
    92479,
    92483,
    92484,
    92485,
    95327,
    95330,
    95331,
    95333
  );

  script_name(english:"MySQL 5.5 < 5.5.31 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.5 installed on the remote host is earlier than
5.5.31 and is, therefore, potentially affected by vulnerabilities in the
following components :

  - Data Manipulation Language
  - Information Schema
  - InnoDB
  - Prepared Statements
  - Server
  - Server Install
  - Server Locking
  - Server Options
  - Server Optimizer
  - Server Partition
  - Server Privileges
  - Server Replication
  - Server XML
  - Stored Procedure");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-31.html");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27b48f62");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e69d66");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.5.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.5.31', min:'5.5', severity:SECURITY_WARNING);
