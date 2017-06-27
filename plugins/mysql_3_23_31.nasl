#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17817);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/10/05 20:44:33 $");

  script_cve_id("CVE-2001-1274");
  script_osvdb_id(9907);

  script_name(english:"MySQL < 3.23.31 Buffer Overflow");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host allows a remote
attacker to exploit a buffer overflow and crash the server, or even
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/306");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 3.23.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/18");
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

mysql_check_version(fixed:'3.23.31', severity:SECURITY_HOLE);
