#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66327);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Lexmark Markvision Enterprise Default Credentials");
  script_summary(english:"Checks for Default Credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application protected with default
credentials."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Lexmark Markvision Enterprise install, a web-based printer
and multi-function device management system, is protected with a set of
known default credentials that allow admin level access to the
application."
  );
  # http://media.lexmark.com/www/asset/en_US/markvision_enterprise_user-guide_en.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?985d438d");
  script_set_attribute(attribute:"solution", value:"Change the password for the admin user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lexmark_markvision_enterprise_detect.nasl", "http_version.nasl");
  script_require_keys("www/lexmark_markvision_enterprise");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 9788);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9788);

install = get_install_from_kb(appname:'lexmark_markvision_enterprise', port:port, exit_on_fail:TRUE);
dir = install['dir'];

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

appname = "Lexmark Markvision Enterprise";
kb_appname = "lexmark_markvision_enterprise";

function get_rand_id()
{
  local_var charset;
  charset = "ABCDEF0123456789";
  return
  rand_str(length:8, charset:charset) + '-' +
  rand_str(length:4, charset:charset) + '-' +
  rand_str(length:4, charset:charset) + '-' +
  rand_str(length:4, charset:charset) + '-' +
  rand_str(length:12, charset:charset);
}

amf_login =
raw_string(0x00,0x03,0x00,0x00,0x00,0x01) +
raw_string(0x00,0x04) +
"null" +
raw_string(0x00,0x02) +
"/2" +
raw_string(0x00,0x00,0x01,0x20) +
raw_string(0x0a,0x00,0x00,0x00,0x01,0x11) +
raw_string(0x0a,0x81) +
  raw_string(0x13, 0x4d) +
  "flex.messaging.messages.CommandMessage" +
  raw_string(0x13) +
  "operation" +
  raw_string(0x1b) +
  "correlationId" +
  raw_string(0x09) +
  "body" +
  raw_string(0x11) +
  "clientId" +
  raw_string(0x13) +
  "messageId" +
  raw_string(0x15) +
  "timeToLive" +
  raw_string(0x0f) +
  "headers" +
  raw_string(0x13) +
  "timestamp" +
  raw_string(0x17) +
  "destination" +
  raw_string(0x04, 0x08) + # int - operation (8)
  raw_string(0x06, 0x01) + # str - correlationID (NULL)
  # body - user:password
  raw_string(0x06) + "9" + base64(str:'admin:Administrator1') +
  raw_string(0x01) + # Client ID (NULL)
  # MessageID
  raw_string(0x06) + 'I' + get_rand_id() +
  raw_string(0x04,0x00) + # int timeToLive (0)
  # headers
    raw_string(0x0a) +
    raw_string(0x0b,0x01,0x15) +
    "DSEndpoint" +
    raw_string(0x06,0x11) + # str
    "blazeamf" + # DSEndpoint
    raw_string(0x09) +
    "DSId" +
    raw_string(0x06) + 'I' + get_rand_id() + #DSid
    raw_string(0x01) +
  raw_string(0x04,0x00) + # int - timestamp (0)
  raw_string(0x06,0x09) + "auth"; # str - Destination, end Object

res = http_send_recv3(
  method:'POST',
  item:'/mve/messagebroker/amf',
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '11,7,700,169'
  ),
  data:amf_login,
  exit_on_fail:TRUE
);

if (
  'User is disabled' >!< res[2] && 
  'Bad credentials' >!< res[2] &&
  'ROLE_ADMIN' >< res[2] && 
  'flex.messaging.messages.AcknowledgeMessage' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + build_url(port:port, qs:dir) + '\n' +
      '  User     : admin\n' +
      '  Password : Administrator1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:'/mve/', port:port));
