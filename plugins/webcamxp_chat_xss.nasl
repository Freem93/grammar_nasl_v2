#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18122);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1189");
  script_bugtraq_id(13250);
  script_xref(name:"OSVDB", value:"15665");

  script_name(english:"WebcamXP Chat Name XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of webcamXP, a webcam software
package and integrated web server for Windows, that suffers from an
HTML injection flaw in its chat feature.  An attacker can exploit this
flaw by injecting malicious HTML and script code through the nickname
field to redirect chat users to arbitrary sites, steal authentication
cookies, and the like." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Apr/405");
 script_set_attribute(attribute:"solution", value:
"Upgrade to webcamXP version 2.16.478 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/18");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for cross-site scripting vulnerability in WebcamXP Chat");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  # nb: this particular web server does not seem vulnerable to general XSS
  #     attacks so we don't have a dependency on cross_site_scripting.nasl.
  script_dependencies("find_service1.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8080);
banner = get_http_banner(port:port);
if (!banner || "webcamXP" >!< banner) exit(0);

# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";

test_cgi_xss(port: port, cgi: "/chat", qs: "nickname="+urlencode(str:xss),
  pass_str: xss);
