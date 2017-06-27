#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
  script_id(10577);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2014/05/26 00:33:32 $");

  script_bugtraq_id(2280);
  script_osvdb_id(475);

  script_name(english:"Microsoft IIS bdir.htr Arbitrary Directory Listing");
  script_summary(english:"Check for existence of bdir.htr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file bdir.htr is a default IIS files which can give a malicious
user a lot of unnecessary information about your file system.
Specifically, the 'bdir.htr' script allows the user to browser and
create files on hard drive. As this includes critical system files, it
is highly possible that the attacker will be able to use this script
to escalate privileges and gain 'Administrator' access.");
  script_set_attribute(attribute:"solution", value:
"If you do not need these files, then delete them, otherwise use
suitable access control lists to ensure that the files are not
world-readable.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"1998/12/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"Copyright (C) 2000-2014 John Lampe <j_lampe@bellsouth.net>");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_port_state(port))
{
    if(is_cgi_installed_ka(item:"/scripts/iisadmin/bdir.htr", port:port))
    {
        security_warning(port);
        exit(0);
    }
}

