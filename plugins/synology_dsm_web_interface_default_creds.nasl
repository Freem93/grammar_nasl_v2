#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93560);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_osvdb_id(136411);

  script_name(english:"Synology DiskStation Manager (DSM) Web Administration Interface Default Credentials");
  script_summary(english:"Attempts to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The Synology DiskStation Manager (DSM) web administration interface
running on the remote host uses a known set of default credentials.");
  script_set_attribute(attribute:"description", value:
"The web administration interface for the Synology DiskStation Manager
(DSM) application running on the remote host uses a default blank
password for the administrator account. A remote attacker can exploit
this to gain administrative access to the web interface.");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials. Alternatively,
upgrading to DiskStation Manager version 6.0-7321 or later will cause
administrative accounts with blank passwords to be disabled after the
upgrade, and consequently a password reset will be required.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:T/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://www.synology.com/en-global/releaseNote/DS114");
  # https://www.synology.com/en-us/knowledgebase/DSM/tutorial/General/How_do_I_log_in_if_I_forgot_the_admin_password
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b85db768");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:synology:diskstation_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("synology_diskstation_manager_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 5000, 5001);
  script_require_keys("www/synology_dsm");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Synology DiskStation Manager (DSM)";
port = get_http_port(default:5001, embedded:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

appname = "synology_dsm";
get_install_count(app_name:appname, exit_if_zero:TRUE);
install = get_single_install(
  app_name: appname,
  port: port,
  exit_if_unknown_ver:FALSE);
dir = install['path'];


url = dir + '/login.cgi?enable_syno_token=yes';
install_url = build_url(qs:url, port:port);
postdata = 'username=admin&passwd=&OTPcode=&__cIpHeRtExT=&client_time=0&isIframeLogin=yes';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  add_headers     : make_array('Referer', install_url),
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE);

# SynoToken is only in the response body if we
# have successful auth. We will also see a Set-Cookie
# header for the 'id' session cookie for successful auth.
if ("SynoToken" >< res[2] && 'Set-Cookie' >< res[1])
{
  report = '\nNessus was able to authenticate to the remote host using the username' +
           '\n"admin" with a blank password within the following request :' +
           '\n\n' +
           http_last_sent_request() +
           '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
