#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17799);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/17 12:36:27 $");

  script_cve_id("CVE-2004-0388");
  script_bugtraq_id(10142);
  script_osvdb_id(6421);

  script_name(english:"MySQL < 4.1.2 Insecure Temporary File Creation");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be overwritten on the remote database server.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.1.2 and reportedly allows a local user to overwrite files via a
symlink attack.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-2.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 4.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/14");
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

mysql_check_version(fixed:'4.1.2', severity:SECURITY_NOTE);
