#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17820);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/09/19 13:28:33 $");

  script_cve_id("CVE-2003-0150");
  script_bugtraq_id(7052);
  script_osvdb_id(9909);
  script_xref(name:"CERT", value:"203897");

  script_name(english:"MySQL < 3.23.56 Writable Configuration Files");
  script_summary(english:"Checks version of MySQL Server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL installed on the remote host is older than
3.23.56.  As such, it reportedly creates world-writeable files.  By
restarting the MySQL daemon under root ID, a local attacker could gain
root privileges.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104802285012750&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104739810523433&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=104715840202315&w=2");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 3.23.56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/08");
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

mysql_check_version(fixed:'3.23.56', severity:SECURITY_HOLE);
