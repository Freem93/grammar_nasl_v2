#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17802);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2006-4031");
  script_bugtraq_id(19279);
  script_osvdb_id(27703);

  script_name(english:"MySQL < 4.1.21 / 5.0.24 Privilege Persistence");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server allows a local user to access unauthorized
data.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is earlier than
4.1.21 / 5.0.24 and thus reportedly allows a local user to access a
table after his privileges on it were revoked.");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-21.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-24.html");
  # 4.1 has reached its end of life.
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL version 5.0.24 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

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

mysql_check_version(fixed:make_list('4.1.21', '5.0.24'), severity:SECURITY_NOTE);
