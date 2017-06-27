#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17825);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/19 12:07:17 $");

  script_cve_id("CVE-2006-4380");
  script_bugtraq_id(19794);
  script_osvdb_id(28296);

  script_name(english:"MySQL < 4.1.13 Denial of Service");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.1.13.  On these versions, a local attacker could crash the
replication slave via a specific query.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=10442");
  script_set_attribute(attribute:"see_also", value:"http://lists.mysql.com/internals/26123");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:'4.1.13', severity:SECURITY_NOTE);
