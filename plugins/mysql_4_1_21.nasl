#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17800);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/17 12:36:27 $");

  script_cve_id("CVE-2006-3469");
  script_bugtraq_id(19032);
  script_osvdb_id(27416);

  script_name(english:"MySQL < 4.1.21 / 5.0 Denial of Service");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.1.21 / 5.0 and reportedly allows a remote, authenticated user to
crash the server via a format string attack.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=20729");
  # 4.1 has reached its end of life
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

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

mysql_check_version(fixed:make_list('4.1.21', '5.0'), severity:SECURITY_HOLE);
