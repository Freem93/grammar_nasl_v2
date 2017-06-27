#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10062);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2014/05/25 23:51:31 $");

 script_cve_id("CVE-1999-1533");
 script_bugtraq_id(665);
 script_osvdb_id(13556);

 script_name(english:"Eicon Technology Diva LAN ISDN Modem login.htm Long password Field DoS");
 script_summary(english:"overflows a remote buffer");

 script_set_attribute(attribute:"synopsis", value:"The remote modem has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be an Eicon Technology Diva LAN ISDN modem.

Nessus crashed the modem by supplying a long password to the login
page. This is likely due to a buffer overflow. A remote attacker could
exploit this by repeatedly disabling the modem.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=93846522511387&w=2");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this modem's firmware.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/09/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/09/28");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"Denial of Service");

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port:port))
 exit(0, "The web server on port "+port+" is already dead.");

r = http_send_recv3(port:port, method:"GET", item: string("/login.htm?password=", crap(200)), exit_on_fail: 0);
if (http_is_dead(port:port, retry: 2)) security_hole(port);


