#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10246);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/05/26 16:30:02 $");

 script_cve_id("CVE-2000-0213");
 script_bugtraq_id(1002);
 script_osvdb_id(194, 5802);

 script_name(english:"Sambar Server Multiple Script Arbitrary Code Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/{hello,echo}.bat");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"At least one of these CGI scripts is installed :

 hello.bat echo.bat

They allow any attacker to execute commands with the privileges of the
web server process.");
 script_set_attribute(attribute:"solution", value:"Delete all the *.bat files from your cgi-bin/ directory");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/02/23");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/sambar");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default: 80);

if (is_cgi_installed3(item:"hello.bat", port:port) ||
    is_cgi_installed3(item:"echo.bat", port:port))
  security_hole(port);

