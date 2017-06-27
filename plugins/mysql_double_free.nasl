#
# (C) Tenable Network Security, Inc.
#

#
# Ref: http://www.mysql.com/doc/en/News-3.23.55.html
# 


include("compat.inc");

if (description)
{
 script_id(11299);  
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2014/05/02 03:09:37 $");

 script_cve_id("CVE-2003-0073");
 script_bugtraq_id(6718);
 script_osvdb_id(9910);
 script_xref(name:"RHSA", value:"2003:093-01");

 script_name(english:"MySQL < 3.23.55 mysql_change_user() Double-free Memory Pointer DoS");
 script_summary(english:"Checks for the remote MySQL version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database service is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"According to its banner, a version of MySQL before 3.23.55 is running
on the remote host.  If you have not patched this version, then an
attacker with valid credentials may be able to crash this service
remotely by exploiting a double free bug. 

Further exploitation to gain a shell on the host might be possible,
although it's unconfirmed so far.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL 3.23.55 or newer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
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
    version =~ "^3\.(([0-9]\..*|(1[0-9]\..*)|(2[0-2]\..*))|23\.([0-4][0-9]|5[0-4])[^0-9])"
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
