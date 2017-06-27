#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59246);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_name(english:"Apache OFBiz Default Credentials");
  script_summary(english:"Attempts to login to an OFBiz app with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote Apache OFBiz application by
providing default credentials. A remote attacker can exploit this
issue to perform administrative actions.");
  # https://cwiki.apache.org/OFBTECH/apache-ofbiz-technical-production-setup-guide.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b05b2aa5");
  script_set_attribute(attribute:"solution", value:"Secure each account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:open_for_business_project");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ofbiz_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/ofbiz/port");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


global_var port;

function login()
{
  local_var dir, user, pass, success, postdata, login_page, logout_page, res;
  dir = _FCT_ANON_ARGS[0];
  user = _FCT_ANON_ARGS[1];
  pass = _FCT_ANON_ARGS[2];
  success = FALSE;

  login_page = dir + '/control/login';
  logout_page = dir + '/control/logout';

  postdata = 'USERNAME=' + user + '&PASSWORD=' + pass;
  res = http_send_recv3(
    method:'POST',
    item:login_page,
    port:port,
    data:postdata,
    content_type:'application/x-www-form-urlencoded',
    exit_on_fail:TRUE
  );

  # the username doesn't seem to be displayed for any of the default ofbiz apps,
  # checking for the presence of a logout link should be good enough
  if (
    '<a href="' + logout_page + '">' >< res[2] &&
    '<form method="post" action="' + login_page + '" name="loginform"' >!< res[2]
  )
  {
    success = TRUE;
    res = http_send_recv3(method:'GET', item:logout_page, port:port, exit_on_fail:TRUE);  # response is ignored
  }

  return success;
}


port = get_kb_item_or_exit('www/ofbiz/port');
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

webapps = make_list(
  'ordermgr',
  'example',
  'bi',
  'birt',
  'partymgr',
  'content',
  'workeffort',
  'catalog',
  'facility',
  'manufacturing',
  'accounting',
  'ar',
  'ap',
  'humanres',
  'marketing',
  'sfa',
  'ofbizsetup',
  'ecommerce',
  'hhfacility',
  'assetmaint',
  'ismgr',
  'ofbiz',
  'projectmgr',
  'oagis',
  'googlebase',
  'googlecheckout',
  'ebay',
  'ebaystore',
  'myportal',
  'webpos',
  'webtools'
);

# only need to test one of the apps that was detected
ofbizapp = NULL;
for (i = 0; i < max_index(webapps) && isnull(ofbizapp); i++)
  ofbizapp = get_install_from_kb(appname:'ofbiz_' + webapps[i], port:port);

if (isnull(ofbizapp))
  audit(AUDIT_WEB_FILES_NOT, 'OFBiz', port);

vuln_accounts = NULL;
accts['admin'] = 'ofbiz';
accts['flexadmin'] = 'ofbiz';
accts['demoadmin'] = 'ofbiz';
accts['ltdadmin'] = 'ofbiz';
accts['externaluser'] = 'ofbiz';
accts['DemoBuyer'] = 'ofbiz';
accts['DemoRepAll'] = 'ofbiz';

foreach user (keys(accts))
{
  if (login(ofbizapp['dir'], user, accts[user]))
    vuln_accounts[ofbizapp['dir']][user] = accts[user];
}

if (isnull(vuln_accounts)) audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  foreach dir (sort(keys(vuln_accounts)))
  {
    report +=
      '\n' + 'Nessus logged into the following page :' +
      '\n' +
      '\n' + '  URL : ' + build_url(qs:dir + '/control/checkLogin', port:port) +
      '\n' +
      '\n' + 'Using the following credentials :' +
      '\n';

    foreach user (sort(keys(vuln_accounts[dir])))
    {
      report +=
        '\n  Username : ' + user +
        '\n  Password : ' + vuln_accounts[dir][user] +
        '\n';
    }
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
