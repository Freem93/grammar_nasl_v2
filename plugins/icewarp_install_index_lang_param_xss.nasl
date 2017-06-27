#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(53869);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/14 03:46:10 $");

  script_bugtraq_id(47723);
  script_osvdb_id(72132);
  script_xref(name:"Secunia", value:"44425");

  script_name(english:"IceWarp install/index.html lang Parameter XSS");
  script_summary(english:"Tries to inject a payload");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
cross-site scripting attack.");

  script_set_attribute(attribute:"description", value:
"The remote web server hosts a PHP script that is susceptible to a
cross-site scripting attack.  The script 'install/index.html' does not
properly sanitize input data to the 'lang' parameter before including
it in HTML generated dynamically. 

As a result of this vulnerability, it is possible for a remote
attacker to create a malicious link containing script code that will
be executed in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication
credentials as well as other attacks.");
  
  # http://web.archive.org/web/20110410070136/http://www.icewarp.com/download/whatsnew-10.3.0.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3403f32c");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 10.3.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2011/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:icewarp:webmail");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80, 32000);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:32000, php:TRUE);

# Is this IceWarp?
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if ("IceWarp" >!< banner) exit(0, "The web server listening on port "+port+" does not look like IceWarp.");
}

# Try XSS.
magic = unixtime() + SCRIPT_NAME;
exploit_1 = '"/><script>alert(/'+magic+'/)</script>';
query_str = 'lang='+exploit_1;

if (!test_cgi_xss(
  port     : port, 
  dirs     : make_list(""), 
  cgi      : "/install/index.html", 
  qs       : query_str,
  pass_str : "&lang="+exploit_1,
  pass_re  : '<title>IceWarp Utilities</title>',
  pass2_re : "\?(linux|windows|mac)&lang=.*"+magic
)) exit(0, "The IceWarp install on port "+port+" is not affected.");
