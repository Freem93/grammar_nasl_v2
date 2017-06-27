#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18540);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-2021");
  script_bugtraq_id(13996);
  script_osvdb_id(17399);

  script_name(english:"cPanel cpsrvd.pl user Parameter XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is prone to a cross-site
scripting attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running cPanel. 

The version of cPanel on the remote host suffers from a cross-site
scripting vulnerability due to its failure to sanitize user-supplied
input to the 'user' parameter of the 'login' page.  An attacker may be
able to exploit this flaw to inject arbitrary HTML and script code
into a user's browser." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/22");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_cvs_date("$Date: 2015/01/13 20:37:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:cpanel:cpanel");
script_end_attributes();

 
  summary["english"] = "Checks for user parameter cross-site scripting vulnerability in cPanel";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 2086);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:2086);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

xss = "regex m/^** << HERE <script>JavaScript:alert('" + SCRIPT_NAME + "');</script>";
exss = "%3Cscript%3EJavaScript:alert('" + SCRIPT_NAME + "')%3B%3C%2Fscript%3E";

r = http_send_recv3(method:"GET",item:string("/login?user=**", exss), port:port);
if (isnull(r)) exit(0);
# cPanel does not return a proper HTTP header on errors
res = strcat(r[0], r[1], '\r\n', r[2]);

if (xss >< res)
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

