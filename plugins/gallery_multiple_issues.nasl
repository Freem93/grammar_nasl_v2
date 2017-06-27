#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16185);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2005-0220");
  script_bugtraq_id(12292, 12286);
  script_osvdb_id(13029, 13030, 13031, 13032, 13033, 13034, 13922);

  script_name(english:"Gallery login.php username Parameter XSS");
  script_summary(english:"Attempts to inject script code via login.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server is affected by a
cross-site scripting vulnerability because it fails to properly sanitize
user-supplied input to the 'username' parameter of the 'login.php'
script.  An attacker could exploit this flaw to inject arbitrary HTML
and script code into a user's browser to be executed within the security
context of the affected site. 

Note that the application is reportedly affected by multiple additional
cross-site scripting vulnerabilities as well as an information
disclosure vulnerability, although Nessus has not tested for these."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jan/210");
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/147");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.4.4-pl5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("gallery_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/gallery", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];

if (get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

exploit = '"<script>' + SCRIPT_NAME + '</script';

res = http_send_recv3(
  method : "GET",
  item   : dir + '?username=' + exploit,
  port   : port,
  exit_on_fail : TRUE
);

if ('<input type=text name="username" value=""<script>' + SCRIPT_NAME + '</script>"' >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
