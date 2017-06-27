#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10011);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2014/05/25 01:17:39 $");

 script_cve_id("CVE-1999-0885");
 script_bugtraq_id(770);
 script_osvdb_id(11);

 script_name(english:"Alibaba get32.exe Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/get32.exe");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary command may be run on this server.");
 script_set_attribute(attribute:"description", value:
"The 'get32.exe' CGI script is installed on this machine. This CGI has
a well known security flaw that allows an attacker to execute
arbitrary commands on the remote system with the privileges of the
HTTP daemon (typically root or nobody).");
 script_set_attribute(attribute:"solution", value:
"Remove the 'get32.exe' script from your web server's CGI directory
(usually cgi-bin/)..");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/11/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/04");

script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
if (is_cgi_installed3(item:"get32.exe", port:port))
 security_hole(port);
