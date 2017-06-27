#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10035);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-1999-0146");
 script_bugtraq_id(1975);
 script_osvdb_id(29);

 script_name(english:"NCSA Campas cgi-bin Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/campas");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be NCSA httpd. This version of the
web server comes with a sample CGI script, campas, that fails to
properly sanitize user input. This could allow a remote attacker to
execute arbitrary commands with the privileges of the web server.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=87602661419302&w=2");
 script_set_attribute(attribute:"solution", value:"Remove the script from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/09/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

res = is_cgi_installed3(item:"campas", port:port);
if(res)security_hole(port);
