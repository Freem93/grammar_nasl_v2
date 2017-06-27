#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73685);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:12 $");

  script_osvdb_id(99145);

  script_name(english:"NAS4Free Web UI Default Credentials");
  script_summary(english:"Tries to login with the default credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is protected using default
credentials.");
  script_set_attribute(attribute:"description", value:
"The NAS4Free web interface on the remote host has the 'admin' user
account secured with the default password. A remote, unauthenticated
attacker could exploit this to gain administrative access to the web
interface, which could allow arbitrary command execution via exec.php.");
  # http://wiki.nas4free.org/doku.php?id=documentation:setup_and_user_guide:basic_configuration
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b4a9690");
  script_set_attribute(attribute:"solution", value:"Secure the 'admin' user account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nas4free:nas4free");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("nas4free_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/nas4free");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/nas4free");
port = get_http_port(default:80);

app_name = "NAS4Free Web Interface";
kb_appname = "nas4free_ui";
install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:FALSE);

if (isnull(install)) audit(AUDIT_NOT_INST, app_name);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/login.php';
full_url = build_url(qs:url, port:port);

user = 'admin';
pass = 'nas4free';

postdata =
  'username=' + user +
  '&password=' + pass;

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:0,
  exit_on_fail:TRUE
);

#Verify you are being redirected to index.php.
if ("Invalid username or password. Please try again." >< res[2] || "index.php" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, full_url);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to log into the ' + app_name + ' using' +
    '\n' + 'the following information :' +
    '\n' +
    '\n  URL      : ' + full_url +
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
