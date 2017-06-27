#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17811);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/11 21:40:58 $");

  script_cve_id("CVE-2008-4456");
  script_bugtraq_id(31486);
  script_osvdb_id(48710);

  script_name(english:"MySQL < 5.0.89 / 5.1.42 / 5.4.2 / 5.5.1 / 6.0.14 Client XSS");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"A remote database client have a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
5.0.89 / 5.1.42 / 5.4.2 / 5.5.1 / 6.0.14 and thus does not properly
encode angle brackets when 'mysql --html' option is used.  Depending
on how the output of the mysql client command is processed, the user
may be vulnerable to cross-site scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=27884");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.0.89 / 5.1.42 / 5.4.2 / 5.5.1 / 6.0.14 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("mysql_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:make_list('5.0.89', '5.1.42', '5.4.2', '5.5.1', '6.0.14'), severity:SECURITY_NOTE);
