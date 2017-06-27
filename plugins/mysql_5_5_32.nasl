#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68938);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/24 04:42:09 $");

  script_cve_id(
    "CVE-2013-1861",
    "CVE-2013-3783",
    "CVE-2013-3793",
    "CVE-2013-3802",
    "CVE-2013-3804",
    "CVE-2013-3809",
    "CVE-2013-3812",
    "CVE-2016-0502"
  );
  script_bugtraq_id(
    58511,
    61210,
    61244,
    61249,
    61260,
    61264,
    61272
  );
  script_osvdb_id(
    91415,
    95322, 
    95323,
    95325,
    95328,
    95332,
    95336,
    133176
  );

  script_name(english:"MySQL 5.5 < 5.5.32 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.5.x installed on the remote host is prior to
5.5.32. It is, therefore, affected by multiple vulnerabilities in the
following components :

  - Audit Log
  - Data Manipulation Language
  - Full Text Search
  - GIS
  - Server : Optimizer
  - Server : Parser
  - Server : Replication");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-32.html");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e69d66");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66027465");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
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

mysql_check_version(fixed:'5.5.32', min:'5.5', severity:SECURITY_WARNING);
