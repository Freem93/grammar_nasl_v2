#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68937);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/09 13:14:19 $");

  script_cve_id("CVE-2013-1861", "CVE-2013-3802", "CVE-2013-3804");
  script_bugtraq_id(58511, 61244, 61260);
  script_osvdb_id(91415, 95325, 95328);

  script_name(english:"MySQL 5.1 < 5.1.70 Multiple Vulnerabilities");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL 5.1 installed on the remote host is earlier than
5.1.70 and is, therefore, potentially affected by vulnerabilities in the
following components :

  - Full Text Search
  - GIS
  - Server Optimizer");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/relnotes/mysql/5.1/en/news-5-1-70.html");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96e69d66");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.1.70 or later.");
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

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.1.70', min:'5.1', severity:SECURITY_WARNING);
