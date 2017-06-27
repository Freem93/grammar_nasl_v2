#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11810);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_cve_id("CVE-2003-0614");
  script_bugtraq_id(8288);
  script_osvdb_id(2322);

  script_name(english:"Gallery search.php searchstring Parameter XSS");
  script_summary(english:"Checks for the presence of search.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is prone to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Gallery hosted on the remote web server is affected by a
cross-site scripting attack due to a failure to properly sanitize
user-supplied input to the 'searchstring' parameter of the 'search.php'
script.  A remote attacker may use this to steal the cookies from the
legitimate users of this system."
  );
  script_set_attribute(attribute:"see_also", value:"http://galleryproject.org/node/82");
  script_set_attribute(attribute:"solution", value:"Upgrade to Gallery 1.3.4-pl1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gallery_project:gallery");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");

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

port = get_http_port(default:80, php:TRUE, no_xss:TRUE);

install = get_install_from_kb(
  appname      : "gallery",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];

r = http_send_recv3(
  method : 'GET',
  item   : dir + "/search.php?searchstring=<script>"+SCRIPT_NAME+"</script>",
  port   : port,
  exit_on_fail : TRUE
);

if (
  r[0] =~ "^HTTP/1\.[01] +200 " &&
  "<script>"+SCRIPT_NAME+"</script>" >< r[2] &&
  "<!-- search.header begin -->" >< r[2]
)
{
  security_warning(port);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Gallery", build_url(qs:dir, port:port));
