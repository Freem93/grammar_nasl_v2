#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35749);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/09/30 16:07:22 $");

  script_cve_id("CVE-2009-0499");
  script_bugtraq_id(33615);
  script_osvdb_id(54085);
  script_xref(name:"Secunia", value:"33775");

  script_name(english:"Moodle Forum 'post.php' Unauthorized Post Deletion CSRF");
  script_summary(english:"Looks for hidden sesskey variable in 'prune.html'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 'forum' code in the version of Moodle installed on the remote host
is affected by a cross-site request forgery vulnerability due to a
failure to properly validate requests before deleting forum posts. If
an attacker can trick a Moodle user into clicking on a malicious link,
this issue could be leveraged to delete the user's posts.

Note that this install is also likely affected by several other
vulnerabilities, including one allowing for arbitrary code execution,
although Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Moodle_1.9.4_release_notes");
  script_set_attribute(attribute:"see_also", value:"http://docs.moodle.org/en/Moodle_1.8.8_release_notes");
  script_set_attribute(attribute:"see_also", value:"http://moodle.org/mod/forum/discuss.php?d=115529");
  script_set_attribute(attribute:"solution", value:"Upgrade to Moodle version 1.9.4 / 1.8.8 / 1.7.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

# Grab prune.html.
url = dir + "/mod/forum/prune.html";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

# There's a problem if it doesn't have the sesskey variable.
if (
  '<form id="pruneform" method="get"' >< res[2] &&
  '<input type="hidden" name="confirm"' >< res[2] &&
  '<input type="hidden" name="sesskey"' >!< res[2]
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
