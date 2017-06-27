#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10346);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2000-0239");
 script_bugtraq_id(1056);
 script_osvdb_id(10887);

 script_name(english:"MERCUR WebView WebMail Server mail_user Parameter DoS");
 script_summary(english:"Checks for a buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote WebView service does not do proper bounds checking when
processing the following request :

 GET /mmain.html&mail_user=aaa[...]aaa

A remote attacker could exploit this to crash the service, or
potentially execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Mar/200");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/03/15");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports(1080);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 1080;

if (! get_port_state(port)) exit(0, "Port "+port+" is closed");

if (http_is_dead(port: port)) exit(0, "Web server on port "+port+" is dead");

req2 = string("/mmain.html&mail_user=", crap(2000));
w = http_send_recv3(port: port, item:req2, method:"GET");
if (isnull(w)) security_hole(port);
