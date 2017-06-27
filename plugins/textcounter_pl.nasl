#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11451);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2014/05/26 16:32:07 $");

 script_cve_id("CVE-1999-1479");
 script_bugtraq_id(2265);
 script_osvdb_id(13537);

 script_name(english:"Matt Wright textcounter.pl Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/textcounter.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a CGI installed that may allow arbitrary code
execution on the remote system.");
 script_set_attribute(attribute:"description", value:
"The CGI 'textcounter' is installed. This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody).");
 script_set_attribute(attribute:"solution", value:"remove it from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/06/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
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
if (get_kb_item("www/no404/" + port)) exit(0);

foreach dir (cgi_dirs())
{
  res = is_cgi_installed3(item:strcat(dir, '/textcounter.pl'), port:port);
  if (res) security_hole(port);
}
