#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17823);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2004-0381");
  script_bugtraq_id(9976);
  script_osvdb_id(6420);

  script_name(english:"MySQL < 4.0.20 File Overwrite");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files could be overwritten on the remote server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
4.0.20.  A local attacker could exploit a flaw in mysqlbug to overwite
arbitrary files via a symlink attack.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=108206802810402&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=108023246916294&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.0.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("mysql_version.inc");

mysql_check_version(fixed:'4.0.20', severity:SECURITY_NOTE);
