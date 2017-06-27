#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72777);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_name(english:"Oracle WebCenter Sites Default Credentials Check");
  script_summary(english:"Tries to login using default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application that uses a default set of
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Oracle WebCenter Sites (formerly known as FatWire Content Server) is
running on the remote host, and Nessus was able to authenticate to it
using a set of known default credentials.  This allows a remote attacker
to gain administrative access to sites running on the server."
  );
  script_set_attribute(attribute:"solution", value:"Change the password for any accounts using default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("oracle_webcenter_sites_detect.nbin");
  script_require_ports("Services/www", 7001);
  script_require_keys("www/oracle_webcenter_sites");
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:7001);

install = get_install_from_kb(
  appname      : "oracle_webcenter_sites",
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];

# trim trailing /
if (dir[strlen(dir) - 1] == '/')
  dir = substr(dir, 0, strlen(dir) - 2);

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : dir,
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

login_page = NULL;

# <META HTTP-EQUIV="Refresh" CONTENT="0;URL=faces/jspx/login.jspx">
# try to parse redirect for login page
if ("UI Login Page" >< res[2])
{
  item = eregmatch(pattern:'<META[^>]*Refresh[^>]*URL=([^"]+)"', string:res[2]);
  if (!isnull(item) && !isnull(item[1]))
    login_page = item[1];
}

# we didn't get a redirect, so search for it
if (isnull(login_page))
{
  login_page_list = make_list(
    'wem/fatwire/wem/Welcome',
    'faces/jspx/login.jspx');

  foreach page (login_page_list)
  {
    res = http_send_recv3(
            port            : port,
            method          : 'GET',
            item            : dir + '/' + page,
            follow_redirect : 1,
            exit_on_fail    : TRUE
          );
    if (res[2] =~ "<title>[ \t]*(FatWire ContentServer|Oracle WebCenter Sites)[^<]*</title>" &&
       "Password" >< res[2] && res[2] =~ "User[ \t]*[Nn]ame")
    {
      login_page = page;
      break;
    }
  }
}

if (isnull(login_page))
  exit(0, "Could not locate a WebCenter Sites login page.");

init_cookiejar();

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : dir + '/' + login_page,
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

post_url = NULL;

# due to how many re-directs this software likes to use,
# we need to find the last url forwarded to
# so we know exactly where we need to post
if (res[2] =~ "<title>[ \t]*(FatWire ContentServer|Oracle WebCenter Sites)[^<]*</title>" &&
       "Password" >< res[2] && res[2] =~ "User[ \t]*[Nn]ame")
{
  lr = http_last_sent_request();
  lr = split(lr, sep:'\n', keep:FALSE);
  if (max_index(lr) == 0) audit(AUDIT_FN_FAIL, 'http_last_sent_request');
  # the last sent HTTP request will be the script we will want to post to
  item = eregmatch(pattern:"GET[ \t]+([^ \t]+)[ \t]+HTTP/1.1$", string:chomp(lr[0]));
  if (isnull(item) || isnull(item[1]))
    exit(1, "Unable to parse last sent HTTP request.");

  post_url = item[1];
}
else exit(1, 'Unable to validate WebCenter Sites Login Page.');

# default credentials to check
creds = make_array('ContentServer', 'password',
                   'fwadmin', 'xceladmin');

info = '';
i = 0;
foreach username (keys(creds))
{
  password = creds[username];

  # each major version has different names for the various login fields,
  # it doesn't hurt sending all the possible fields together in one request
  postdata =
             # 11.x
             'username=' + username +'&' +
             'password=' + password + '&' +
             '_eventId=submit&' +

             # 7.x
             'inputText1=' + username + '&' +
             'inputText2=' + password + '&' +
             'rememberUserCheckBox=t&' +
             'locale=en_US&' +
             'oracle.adf.faces.FORM=form2&'+
             'source=commandButton1';

  ### parse out various anti-csrf tokens as required ###

  # for 11.x
  # <input type="hidden" name="lt" value="_c456E491A-16F1-192A-7492-4097BDB61536_k7E202DDD-C959-A0FF-8708-30C1CEFF203D" />
  item = eregmatch(pattern:'type="hidden"[ \t]*name="lt"[ \t]*value="([^"]+)"', string:res[2]);
  if (!isnull(item) && !isnull(item[1]))
    postdata += '&lt=' + item[1];

  # for 7.x
  # <input type="hidden" name="oracle.adf.faces.STATE_TOKEN" value="1">
  item = eregmatch(pattern:'type="hidden"[ \t]*name="oracle.adf.faces.STATE_TOKEN"[ \t]*value="([^"]+)"', string:res[2]);
  if (!isnull(item) && !isnull(item[1]))
    postdata += '&oracle.adf.faces.STATE_TOKEN=' + item[1];

  res = http_send_recv3(
    port            : port,
    method          : 'POST',
    item            : post_url,
    data            : postdata,
    add_headers     : make_array('Referer', build_url(port:port, qs:post_url)),
    content_type    : "application/x-www-form-urlencoded",
    exit_on_fail    : TRUE
  );

  # check for cookie text in header indicating successful login
   if (("User=true" >< res[1] && "SelectedSite=" >< res[1]) ||
       "CASTGC=TGT" >< res[1])
  {
    info += '\n  Username : ' + username +
            '\n  Password : ' + password + '\n';
  }

  # rebuild a new session to test another login,
  # only if we have more logins to test
  if (i<max_index(keys(creds)))
  {
    clear_cookiejar();

    res = http_send_recv3(
      port            : port,
      method          : 'GET',
      item            : dir + '/' + login_page,
      follow_redirect : 1,
      exit_on_fail    : TRUE
    );
  }
  i++;
}

# report on any found default logins
if (info != '')
{
  report = '\nNessus was able to login using the following credentials :\n' +
           '\n  Login URL : ' + build_url(port:port, qs:dir + '/' + login_page) + '\n' +
           info;
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle WebCenter Sites", port);
