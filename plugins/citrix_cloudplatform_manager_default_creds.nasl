#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79641);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_name(english:"Citrix CloudPlatform Default Credentials");
  script_summary(english:"Tries to log into Citrix CloudPlatform with default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The application on the remote web server uses a default set of known
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix CloudPlatform web administration interface uses a
known set of default credentials.");
  script_set_attribute(attribute:"solution", value:"Change the default 'admin' login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:cloudplatform");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("citrix_cloudplatform_manager_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Citrix CloudPlatform");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("citrix_cloudplatform.inc");

if(supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

appname = "Citrix CloudPlatform";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port    = get_http_port(default:8080);

install = get_single_install(app_name:appname,port:port);
url     = build_url(port:port, qs:install["path"]);
success = make_list();
logins  = make_array(
  'admin','password'
);

foreach user (keys(logins))
{
  pass = logins[user];
  res  = cloudplatform_login(port:port,username:user,password:pass,send_plaintext:TRUE);
  if(typeof(res) == 'array')
  {
    success = make_list(success,user);
    if(!thorough_tests) break; # Only need one successful attempt
  }
  # Weird response, don't attempt any more logins
  else if(res == CITRIX_CP_ERROR_COM) audit(AUDIT_RESP_BAD, port);
}

if(max_index(success) > 0)
{
  if(report_verbosity > 0)
  {
    report = "";
    foreach user (success)
    {
      report +=
        '\n  Username : ' + user +
        '\n  Password : ' + logins[user] + '\n';
    }
    header  = 'Nessus was able to gain access using the following URL';
    trailer = 'using the following set of credentials :\n' + report;
    report  = get_vuln_report(
      items   : "/client/api",
      port    : port,
      header  : header,
      trailer : trailer
    );
    security_hole(port:port,extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url);
