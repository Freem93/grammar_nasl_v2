#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66394);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Citrix NetScaler Web Management Interface Default Administrator Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application is protected using default administrative
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Citrix NetScaler Web Management Interface uses a default
password ('nsroot') for the administrator account ('nsroot'). 

With this information, an attacker can gain complete administrative
access to the Citrix NetScaler appliance."
  );
  # http://support.citrix.com/proddocs/topic/netscaler-admin-guide-93/ns-ag-aa-reset-default-amin-pass-tsk.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74336bf9");
  script_set_attribute(attribute:"solution", value:"Reset the nsroot password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("netscaler_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/netscaler");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/netscaler");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80, embedded:TRUE);


# Try to log in.
user = 'nsroot';
pass = 'nsroot';


# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

logged_in = FALSE;

initial_page = get_kb_item_or_exit("www/netscaler/"+port+"/initial_page");
if (initial_page == "/index.html")
{
  url = '/ws/login.pl?' +
        'username=' + urlencode(str:user) + '&' +
        'password=' + urlencode(str:pass) + '&' +
        'appselect=stat';

  res = http_send_recv3(port:port, method:"GET", item:url, exit_on_fail:TRUE);
  if (
    get_http_cookie(name:"ns1") && 
    get_http_cookie(name:"ns2")
  ) logged_in = TRUE;
}
else
{
  url = "/login/do_login";

  postdata = 'username=' + urlencode(str:user) + '&' +
             'password=' + urlencode(str:pass) + '&' +
             'startin=def' + '&' +
             'timeout=30' + '&' +
             'unit=Minutes' + '&' +
             'jvm_memory=256M' + '&' +
             'url=' + '&' +
             'timezone_offset=-14400';
  res = http_send_recv3(
    port            : port,
    method          : 'POST',
    item            : url,
    data            : postdata,
    content_type    : "application/x-www-form-urlencoded",
    follow_redirect : 1,
    exit_on_fail    : TRUE
  );
  if (
    'Configuration</title>' >< res[2] &&
    '">var neo_logout_url =' >< res[2]
  ) logged_in = TRUE;
}

if (logged_in)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(items:initial_page, port:port, header:header, trailer:trailer);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Citrix NetScaler Web Management Interface", build_url(port:port, qs:initial_page));
