#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11776);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/05/25 02:11:20 $");

 script_cve_id("CVE-2001-0614");
 script_bugtraq_id(2729);
 script_osvdb_id(6591);

 script_name(english:"Carello E-Commerce Carello.dll Command Execution");
 script_summary(english:"Checks for the presence of carello.dll");

 script_set_attribute(attribute:"synopsis", value:"The remote web application has a command execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Carello.dll, a web-based
shopping cart.

Versions up to 1.3 of this web shopping cart have a command execution
vulnerability. This could allow a remote attacker to run arbitrary
commands on the system with the privileges of the web server.

*** Note that no attack was performed, and the version number was ***
not checked, so this might be a false alert");
 script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0012.txt");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of the software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# Please note that it is possible to test this vulnerability, but
# I suspect that Carello is not widely used, and I am lazy :-)
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
res = is_cgi_installed3(item:"Carello.dll", port:port);
if (res) security_hole(port);
