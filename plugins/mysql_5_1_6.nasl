#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17810);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/17 12:36:27 $");

  script_cve_id("CVE-2006-3081");
  script_bugtraq_id(18439);
  script_osvdb_id(27054);

  script_name(english:"MySQL < 4.1.18 / 5.0.19 / 5.1.6 Denial of Service");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is susceptible to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.1.18 / 5.0.19 / 5.1.6 and thus reportedly allows a remote,
authenticated user to crash the server via the str_to_date
function.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=15828");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 4.1.18 / 5.0.19 / 5.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/17");
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

mysql_check_version(fixed:make_list('4.1.18', '5.0.19', '5.1.6'), severity:SECURITY_WARNING);
