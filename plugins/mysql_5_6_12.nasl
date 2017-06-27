#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68939);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/24 04:42:09 $");

  script_cve_id(
    "CVE-2013-1861",
    "CVE-2013-3793",
    "CVE-2013-3795",
    "CVE-2013-3796",
    "CVE-2013-3798",
    "CVE-2013-3802",
    "CVE-2013-3804",
    "CVE-2013-3806",
    "CVE-2013-3807",
    "CVE-2013-3809",
    "CVE-2013-3810",
    "CVE-2013-3811",
    "CVE-2013-3812",
    "CVE-2013-5770",
    "CVE-2016-0502"
  );
  script_bugtraq_id(
    58511,
    61214,
    61233,
    61235,
    61238,
    61241,
    61244,
    61249,
    61252,
    61260,
    61264,
    61272,
    61274,
    63119
  );
  script_osvdb_id(
    91415,
    95321,
    95322,
    95323,
    95324,
    95325,
    95326,
    95328,
    95329,
    95334,
    95335,
    95336,
    95337,
    98513,
    133176
  );

  script_name(english:"MySQL 5.6.x < 5.6.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is 5.6.x older than
5.6.12.  As such, it is reportedly affected by vulnerabilities in the
following components :

  - Audit Log
  - Data Manipulation Language
  - Full Text Search
  - GIS
  - InnoDB
  - Locking
  - MemCached
  - Server Optimizer
  - Server Privileges
  - Server Replication
  - XA Transactions");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-12.html");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e69d66");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?532e14d2");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.6.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
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

mysql_check_version(fixed:'5.6.12', severity:SECURITY_WARNING, min:'5.6');
