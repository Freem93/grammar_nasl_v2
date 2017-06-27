#
# (C) Tenable Network Security, Inc.
#

# References:
# http://marc.info/?l=bugtraq&m=100463639800515&w=2

include("compat.inc");

if (description)
{
 script_id(11107);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2014/05/27 00:15:38 $");

 script_cve_id("CVE-2001-0849");
 script_bugtraq_id(3495);
 script_osvdb_id(13981);

 script_name(english:"Viralator CGI Script Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/viralator.cgi");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow arbitrary code
execution on the remote system.");
 script_set_attribute(attribute:"description", value:
"The CGI 'viralator.cgi' is installed. Some versions of this CGI are
don't check properly the user input and allow anyone to execute
arbitrary commands with the privileges of the web server.

** No flaw was tested. Your script might be a safe version.");
 script_set_attribute(attribute:"solution", value:"Upgrade this script to version 0.9pre2 or later");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

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

if (is_cgi_installed3(port: port, item:"/viralator.cgi"))
  security_hole(port);
