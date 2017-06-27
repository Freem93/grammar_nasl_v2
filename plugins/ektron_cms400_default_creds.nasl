#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46198);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"Ektron CMS400.NET Default Credentials");
  script_summary(english:"Attempts to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"A web application can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the Ektron CMS400.NET install on the remote
host using a default set of credentials.");
  script_set_attribute(attribute:"see_also", value:"http://www.ektron.com/Products/Ektron-CMS/");
  script_set_attribute(attribute:"solution", value:
"Refer to the documentation for instructions on changing the default
account passwords.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ektron_cms400_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cms400","www/ASP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, asp:TRUE);

install = get_install_from_kb(appname:'cms400', port:port,exit_on_fail:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];

url = dir + '/Workarea/login.aspx';
res = http_send_recv3(method:"GET",item:url,port:port,exit_on_fail:TRUE);

state = NULL;
if(egrep(pattern:'__VIEWSTATE" value=".+" />',string:res[2]))
{
  state = strstr(res[2], 'id="__VIEWSTATE" value=') - 'id="__VIEWSTATE" value="';
  state = state - strstr(state, '" />');
}
if (isnull(state)) exit(1, "Could not extract __VIEWSTATE information from "+build_url(port:port, qs:url)+".");
state = urlencode(str:state);

validation = NULL;
if(egrep(pattern:'__EVENTVALIDATION" value=".+" />',string:res[2]))
{
  validation  = strstr(res[2], 'id="__EVENTVALIDATION" value="') - 'id="__EVENTVALIDATION" value="';
  validation  = validation - strstr(validation, '" />');
}

if(isnull(validation)) exit(1, "Could not extract __EVENTVALIDATION information from "+build_url(port:port, qs:url)+".");
validation = urlencode(str:validation);

# List of users listed under
# /workarea/diagnostics/status.aspx (Security tab)

default_users = make_list("builtin","admin","jedit","supermember","admin2","admin3","jadmin","vs","explorer","spanish");

base_req = '__EVENTTARGET=LoginBtn&' +
           '__EVENTARGUMENT=&'       +
           '__VIEWSTATE='            + state      + "&"+
           '__EVENTVALIDATION='      + validation + "&";
info = "";

foreach user (default_users)
{
  # The password parameter used for login request is
  # slightly different across new and older versions.
  # So we try both.

  foreach p (make_list("pwd=","password="))
  {
    data =  base_req + 'username=' + user + '&' + p + user ;
   # Send a login POST request.
    res = http_send_recv3(
      method:"POST",
      item:url,
      port:port,
      add_headers: make_array(
        "Content-Type", "application/x-www-form-urlencoded",
        "Content-Length",strlen(data)),
      data:data,
      exit_on_fail:TRUE
    );

    if('id="LoginSuceededPanel">' >< res[2] && 'You have been logged in' >< res[2])
      info += "User     : " + user + '\n' + "Password : " + user + '\n\n';

    if(info) break;
  }

  if(info && !thorough_tests) break;
}

if(info)
{
  if(report_verbosity > 0)
  {
    report = '\n' +
      "Nessus could log into the remote web application using "+ '\n' +
      "using the following default username/password combination(s)." + '\n\n' +
      "URL      : " + build_url(port:port, qs:url) + '\n\n' +
       info;

   if(!thorough_tests)
     report +=
       '\nNote that only a partial list of default users were verified since\n' +
       "'thorough_tests' was disabled for this scan." + '\n';

    security_hole(port:port,extra:report);
  }
  else
    security_hole(port);

  exit(0);
}
else
 exit(0,"No default username/password combination(s) were found in the Ektron CMS400.NET install at "+ build_url(port:port, qs:url));
