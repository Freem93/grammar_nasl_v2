#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17831);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/01/18 12:35:04 $");

  script_cve_id("CVE-2006-3486");
  script_osvdb_id(28288);

  script_name(english:"MySQL < 5.0.23 / 5.1.12 Denial of Service");
  script_summary(english:"Checks version of MySQL server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
5.0.23 or 5.1.12.  As such, it reportedly is affected by an off-by-one
buffer overflow. 

A local attacker could use this flaw to crash the service.

Note that this vulnerability is disputed as the attacker needs
extensive permissions to launch the attack.  Such permissions allow
him to disrupt the service.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-12.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-23.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=20622");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.23 / 5.1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/22");
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

mysql_check_version(fixed:make_list('5.0.23', '5.1.12'), severity:SECURITY_NOTE);
