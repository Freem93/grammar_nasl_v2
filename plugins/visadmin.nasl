#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10295);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2014/05/27 00:15:38 $");

 script_cve_id("CVE-1999-0970");
 script_bugtraq_id(1808);
 script_osvdb_id(231);

 script_name(english:"OmniHTTPd visadmin.exe Malformed URL DoS");
 script_summary(english:"Checks for the visadmin.exe cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to fill the hard disk of a server running OmniHTTPd by
issuing the request :

 http://omni.server/cgi-bin/visadmin.exe?user=guest

This allows an attacker to crash your web server. This script checks
for the presence of the faulty CGI, but does not execute it.");
 script_set_attribute(attribute:"solution", value:"Remove visadmin.exe from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/06/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
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
banner = get_http_banner(port:port);
if ( ! banner || "OmniHTTP" >!< banner ) exit(0);

foreach dir (cgi_dirs())
{
  res = http_send_recv3(method:"GET", item:string(dir,"/visadmin.exe"), port:port);
  if(isnull(res)) exit(1,"Null response to visadmin.exe request");

  if(res[0] =~ "^HTTP/1\.[0-9.] +200 +") security_warning(port);
}
