#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10071);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/08/29 13:57:36 $");

 script_osvdb_id(62);

 script_name(english:"Multiple Web Server finger CGI Information Disclosure");
 script_summary(english:"Checks for the presence of /cgi-bin/finger");

 script_set_attribute(attribute:"synopsis", value:"An application on the remote web server is leaking information.");
 script_set_attribute(attribute:"description", value:
"The 'finger' CGI is installed. This can be used by a remote attacker
to enumerate accounts on the system. Such information is typically
valuable in conducting additional, more focused attacks.");
 script_set_attribute(attribute:"solution", value:"Remove the script from /cgi-bin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

res = is_cgi_installed3(port:port, item:"finger");
if(res)
{
 security_warning(port);
}
