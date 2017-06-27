#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10252);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/08/29 13:57:37 $");

 script_cve_id("CVE-1999-0509");
 script_osvdb_id(200);

 script_name(english:"Web Server /cgi-bin Shell Access");
 script_summary(english:"Checks for the presence of various shells in /cgi-bin");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands can be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"The remote web server has one of these shells installed in /cgi-bin :
ash, bash, csh, ksh, sh, tcsh, zsh

Leaving executable shells in the cgi-bin directory of a web server may
allow an attacker to execute arbitrary commands on the target machine
with the privileges of the HTTP daemon.");
 script_set_attribute(attribute:"solution", value:"Remove all the shells from /cgi-bin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
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

sh = make_list("ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 foreach s (sh)
 {
  ok = is_cgi_installed3(item:string(dir, "/", s), port:port);
  if(ok)
  {
   security_hole(port);
   exit(0);
  }
 }
}
