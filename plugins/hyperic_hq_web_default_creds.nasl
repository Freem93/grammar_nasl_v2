#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45358);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/18 21:06:04 $");

  script_name(english:"Hyperic HQ Web GUI Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote Hyperic HQ installation using its
default credentials. 

A remote attacker could exploit this to gain administrative control of
the application."
  );
  script_set_attribute(attribute:"solution", value:"Secure the 'hqadmin' account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("hyperic_hq_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 7080);
  script_require_keys("www/hyperic_hq");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");


user = 'hqadmin';
pass = 'hqadmin';

port = get_http_port(default:7080);

install = get_install_from_kb(appname:'hyperic_hq', port:port, exit_on_fail:TRUE);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Gather data to be used in the POST request.
url = install['dir']+'/SignIn.html';
res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

patterns = make_array(
  'posturl', '<form method="post" action="([^"]+)"',
  'formids', '<input type="hidden" name="formids" value="([^"]+)"',
  'seedids', '<input type="hidden" name="seedids" value="([^"]+)"',
  'if4', '<input type="hidden" name="If_4" value="([^"]+)" />',
  'if6', '<input type="hidden" name="If_6" value="([^"]+)" />',
  'if8', '<input type="hidden" name="If_8" value="([^"]+)" />'
);

foreach name (keys(patterns))
{
  match = eregmatch(string:res[2], pattern:patterns[name]);
  if (match) input[name] = match[1];
  else exit(1, 'Error extracting "'+name+'" from '+build_url(qs:url, port:port)+'.');
}

# Then attempt to login.
postdata =
  'formids='+urlencode(str:input['formids'])+'&'+
  'seedids='+urlencode(str:input['seedids'])+'&'+
  'If_4='+urlencode(str:input['if4'])+'&'+
  'If_6='+urlencode(str:input['if6'])+'&'+
  'If_8='+urlencode(str:input['if8'])+'&'+
  'submitname=linksubmit&'+
  'textfield='+user+'&'+
  'textfield_0='+pass;
res = http_send_recv3(
  method:'POST',
  item:input['posturl'],
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  port:port,
  follow_redirect:2,
  exit_on_fail:TRUE
);

login_url = build_url(qs:url, port:port);

if (
  '<a href="/Logout.do">Sign Out</a>' >< res[2] &&
  'About HQ Version' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '
Nessus was able to gain access using the following information :

  URL      : '+login_url+'
  User     : '+user+'
  Password : '+pass+'
';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Hyperic HQ", login_url);

