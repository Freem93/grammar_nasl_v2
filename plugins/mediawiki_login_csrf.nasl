#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45438);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_bugtraq_id(39270);
  script_xref(name:"Secunia", value:"39333");

  script_name(english:"MediaWiki Login Cross-Site Request Forgery");
  script_summary(english:"Checks if the login page requires a hidden token.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application running on the remote host is affected by a
cross-site request forgery vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of MediaWiki running on the remote host is affected by a
cross-site request forgery vulnerability involving its login page. A
user with a valid wiki account can cause others to unwittingly log
into that account.

A remote attacker can exploit this by tricking a user into making a
maliciously crafted request, causing them to log into the attacker's
account. If the wiki is configured to allow user scripts, this could
allow the attacker to obtain the victim's password."
  );
  # http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-April/000090.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2e32ad4");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.15.3 / 1.6.0beta2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

url = '/index.php?title=Special:UserLogin';
res = http_send_recv3(method:'GET', item:dir+url, port:port, exit_on_fail:TRUE);

# First make sure this looks like the MediaWiki login page.
if (
  '<title>Log in / create account' >!< res[2] &&
  "<input type='password' class='loginPassword'" >!< res[2]
)
{
  login_url = build_url(qs:dir+url, port:port);
  exit(0, login_url+' does not appear to be the MediaWiki login page.');
}

# Then check if the anti-csrf token is present.
token_pattern = '<input type="hidden" name="wpLoginToken" value="[0-9a-f]+" />';
if (egrep(string:res[2], pattern:token_pattern))
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue exists using the following ' +
      'URL :\n' +
      '\n' + install_url + url + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
