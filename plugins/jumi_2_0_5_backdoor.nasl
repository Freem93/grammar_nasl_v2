#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42820);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/19 13:58:07 $");

  script_bugtraq_id(36883);
  script_osvdb_id(59465);

  script_name(english:"Jumi Component for Joomla! <= 2.0.5 Backdoor Detection");
  script_summary(english:"Looks for script created by the backdoor.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
backdoor allowing the execution of arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of Joomla! running on the remote host is affected by a
backdoor that is part of a trojan installation of Jumi, a third-party
component used for including custom code into Joomla!. An
unauthenticated, remote attacker can exploit this backdoor, by using
specially crafted input to the 'key' and 'php' parameters of the
modules/mod_mainmenu/tmpl/.config.php script, to execute arbitrary PHP
code, subject to the privileges of the web server user ID.

Note that Jumi versions 2.0.4 and 2.0.5 are known to have been used as
a trojan installation. It is also likely that the backdoor sends
information about Joomla's configuration, including administrative and
database credentials, to a third party during the component's
installation.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507595/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/archive/p/jumi/issues/45");
  script_set_attribute(attribute:"solution", value:
"Remove the affected backdoor script, change credentials used by
Joomla!, and investigate whether the affected server has been
compromised.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Joomla!", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "Jumi";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('(<name>Jumi<|Jumi package)');
  checks["/components/com_jumi/release_notes.txt"] = regexes;
  checks["/administrator/components/com_jumi/plugin/jumi.xml"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# Check for the backdoor.

subdirs = make_list("/modules/mod_mainmenu/tmpl", "/tmp");

foreach subdir (subdirs)
{
  url = subdir + "/.config.php";
  res = http_send_recv3(port:port, method:"GET", item:dir + url, fetch404: TRUE, exit_on_fail: TRUE);
  # There's a problem if...


  # we see the response header added by the script and...
  if ("HTTP/1.0 404 Not Found" >!< res[0]) continue;
  # And there's no response body
  if (strlen(res[2]) > 0) continue;

  # Anti FP
  u = subdir + "/.config.php?key[0]=42";
  w = http_send_recv3(port:port, method:"GET", item:dir+u, fetch404: TRUE, exit_on_fail: TRUE);

  if ( w[0] !~ "^HTTP/1\.[01] 200 " ||
       "md5() expects parameter 1 to be string, array given" >!< w[2])
  {
    # The check fails. Either this is not the backdoor or php_err is not set
    # Let's try something else...
    u2 = dir + subdir + "/." + rand_str() + ".php";
    w = http_send_recv3(port:port, method:"GET", item:u2, fetch404: TRUE, exit_on_fail: TRUE);
    if ("HTTP/1.0 404 Not Found" >< w[0] && strlen(w[2]) == 0) continue;
  }

  report =
    '\n'+
    'Nessus was able to verify the issue based on the HTTP response headers\n'+
    'received from the following URLs :\n' +
    '\n' +
    '\n' + install_url + url + '\n\n' +
    install_url + u + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
