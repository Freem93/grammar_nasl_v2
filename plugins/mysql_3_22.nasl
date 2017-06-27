#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17815);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/01/18 12:35:04 $");

  script_cve_id("CVE-1999-1188");
  script_osvdb_id(6605);

  script_name(english:"MySQL < 3.22 Readable Logs");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is vulnerable to information
disclosure.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host reportedly creates
world-readable log files, thus allowing local users to get sensitive
information, such as the passwords for newly created users.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=91479159617803&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 3.22 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/12/27");
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

mysql_check_version(fixed:'3.22', severity:SECURITY_WARNING);
