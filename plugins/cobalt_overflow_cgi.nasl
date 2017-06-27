#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11190);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-2002-1361");
 script_osvdb_id(8513);
 script_xref(name:"CERT-CC", value:"CA-2002-35");

 script_name(english:"Cobalt RaQ4 Administrative Interface overflow.cgi Command Execution");
 script_summary(english:"Checks for the presence of a CGI");

 script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host has a command execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"/cgi-bin/.cobalt/overflow/overflow.cgi was detected. Some versions of
this CGI allow remote users to execute arbitrary commands with the
privileges of the web server.

*** Nessus just checked the presence of this file *** but did not try
to exploit the flaw, so this might *** be a false positive.");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:sun:cobalt_raq_4");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");

 script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 81, 444);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_hole(port);
