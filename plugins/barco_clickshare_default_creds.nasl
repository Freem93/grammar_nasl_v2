#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

appname = "Barco ClickShare";

if (description)
{
  script_id(77249);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_osvdb_id(123672);

  script_name(english:"Barco ClickShare Device Default Credentials");
  script_summary(english:"Attempts to login using default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Barco ClickShare administration interface uses a default
set of known credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the web administration interface on the
remote Barco ClickShare device using a default set of known
credentials. A remote attacker can exploit this to gain administrative
control of the device.");
  # http://www.barco.com/en/Products-Solutions/Presentation-collaboration/Clickshare-wireless-presentation-system
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?236478e4");
  script_set_attribute(attribute:"solution", value:"Change the password for the default 'admin' account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:barco:clickshare");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("barco_clickshare_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/" + appname);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# check that detection plugin picked device up
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

username = "admin";
password = "admin";

res = http_send_recv3(method: "GET",
                      item:"/status.php",
                      port:port,
                      username:username,
                      password:password,
                      exit_on_fail:TRUE);

if('>Firmware Version<' >< res[2] &&
   '>Serial Number:<' >< res[2] &&
   '"SettingsTable"' >< res[2] &&
   res[2] =~ 'Barco[ \n\r-]*ClickShare')
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to gain access using the following URL :' +
             '\n' +
             '\n' + '  ' + build_url(port:port, qs:'/') +
             '\n' +
             '\n' + 'and the following set of credentials :\n' +
             '\n  Username : ' + username +
             '\n  Password : ' + password + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));
