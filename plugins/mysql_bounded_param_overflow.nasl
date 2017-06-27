#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 
 script_id(14831);  
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/02/11 00:06:37 $");

 script_cve_id("CVE-2004-2149");
 script_bugtraq_id(11261);
 script_osvdb_id(10244);
 
 script_name(english:"MySQL libmysqlclient Prepared Statements API Overflow");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote code execution 
vulnerability.");
 script_set_attribute(attribute:"description", value:
"You are running a version of MySQL 4.1.x, which is older than version 4.1.5.

There is a flaw in the remote version of this software that could allow
an attacker to crash the affected service, thus denying access to
legitimate users.");
 script_set_attribute(attribute:"see_also", value:"http://bugs.mysql.com/bug.php?id=5194");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 4.1.5 or later, as this reportedly fixes the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

if (mysql_init(port:port, exit_on_fail:TRUE) == 1)
{
  version = mysql_get_version();

  if (
    strlen(version) &&
    version =~ "^4\.1\.[0-4][^0-9]"
  )
  {
    if (report_verbosity > 0)
    {
      report = '\nThe remote MySQL server\'s version is :\n\n  '+version+'\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
}
mysql_close();

