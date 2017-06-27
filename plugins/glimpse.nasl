#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10095);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2014/05/26 00:12:07 $");

 script_cve_id("CVE-1999-0147");
 script_bugtraq_id(2026);
 script_osvdb_id(82);

 script_name(english:"Glimpse HTTP aglimpse Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/phf");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a web application that is affected by
an arbitrary command execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server is running GlipmseHTTP. The installed version
suffers from a remote command execution vulnerability in the
'aglimpse' component.

Note that we could not actually check for the presence of this
vulnerability, and only checked for the existence of the 'aglimpse'
CGI.");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/07/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
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
cgi = "aglimpse";
if (is_cgi_installed3(item:cgi,port:port)) security_hole(port);
