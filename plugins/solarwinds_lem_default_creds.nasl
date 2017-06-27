#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78916);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_name(english:"SolarWinds Log and Event Manager Default Credentials");
  script_summary(english:"Checks for default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application protected with default
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote SolarWinds Log and Event Manager install, a security
information and event management (SIEM) solution, is protected with a
set of known default credentials that allow administrator level access
to the appliance.");
  # http://knowledgebase.solarwinds.com/kb/questions/4085/Resetting+the+Admin+password
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e583e3fd");
  script_set_attribute(attribute:"solution", value:"Change the password for the 'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:log_and_event_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("solarwinds_lem_detect.nbin", "http_version.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/SolarWinds Log and Event Manager");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app  = "SolarWinds Log and Event Manager";
port = get_http_port(default:8080);

install = get_single_install(app_name: app, port: port);

dir     = install['path'];
install_url = build_url(port:port, qs:dir);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Creates random ID (e.g. 55F580EF-970E-39CB-38EB-F0624A9E0B3E)
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

# Tracking pattern
tracking_id_pat = '(I[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})';
tracking_id     = NULL;

init_cookiejar();

amf_header =
  raw_string(0x00,0x03,0x00,0x00,0x00,0x01) + # AMF version 3
  raw_string(0x00,0x04) +
  "null" +
  raw_string(0x00,0x02);

# AMF object is used in all AMF POST data
amf_obj =
  raw_string(0x0a,0x81, 0x13, 0x4d) +
  "flex.messaging.messages.CommandMessage" +
  raw_string(0x13) +
  "operation" +
  raw_string(0x1b) +
  "correlationId" +
  raw_string(0x17) +
  "destination" +
  raw_string(0x13) +
  "messageId" +
  raw_string(0x15) +
  "timeToLive" +
  raw_string(0x09) +
  "body" +
  raw_string(0x0f) +
  "headers" +
  raw_string(0x11) +
  "clientId" +
  raw_string(0x13) +
  "timestamp";

# DSId - session id
dsid = "I" + get_rand_id();


# Packet 1 - Initialize session and retrieve cookie
init_req =
  amf_header +
  "/1" +
  raw_string(0x00, 0x00, 0x00, 0xe0) + # length: 224
  raw_string(0x0a,0x00,0x00,0x00,0x01,0x11) + # strict array
  amf_obj +
  raw_string(0x04, 0x05) + # int - operation (8)
  raw_string(0x06, 0x01) +
  raw_string(0x06, 0x01, 0x06, 0x49) +
  get_rand_id() +
  raw_string(0x04, 0x00, 0x0a, 0x0b, 0x01, 0x01, 0x0a, 0x05) +
  raw_string(0x25) +
    "DSMessagingVersion" +
    raw_string(0x04, 0x01, 0x09) +
    "DSId" +
    raw_string(0x06, 0x07) +
    "nil" +
    raw_string(0x01) +
  raw_string(0x01, 0x04, 0x00);

uri = '/services/messagebroker/nonsecureamf';

res = http_send_recv3(
  method:'POST',
  item:uri,
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '15,0,0,167'
  ),
  data:init_req,
  exit_on_fail:TRUE
);

matches = pregmatch(string:res[2], pattern:tracking_id_pat);
if (!isnull(matches[1]))
  tracking_id = matches[1];
else
  exit(1, "An unexpected response was received after sending the first packet.");


# Packet 2 - Send login credentials
creds = 'admin:password';

amf_login =
  amf_header +
  "/2" +
  raw_string(0x00, 0x00, 0x01, 0x2a) + # length:
  raw_string(0x0a,0x00,0x00,0x00,0x01,0x11) + # strict array
  amf_obj +
  raw_string(0x04, 0x08) + # int - operation (8)
  raw_string(0x06, 0x01, 0x06, 0x09) +
  "auth" +
  raw_string(0x06) +
#  "I" + get_rand_id() +
  tracking_id +
  raw_string(0x04, 0x00, 0x06, 0x29) +
  base64(str:creds) + # body - user:password
  raw_string(0x0a, 0x0b, 0x01, 0x09) + # object - no name
    "DSId" +
    raw_string(0x06) +
    dsid + #DSid
    raw_string(0x15) +
    "DSEndpoint" +
    raw_string(0x06, 0x35) +
    "non-secure-non-polling-amf" +
    raw_string(0x01) + # end of dynamic members
  raw_string(0x01, 0x04, 0x00);

res = http_send_recv3(
  method:'POST',
  item:uri,
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '15,0,0,167'
  ),
  data:amf_login,
  exit_on_fail:TRUE
);

matches = pregmatch(string:res[2], pattern:tracking_id_pat);
if (!isnull(matches[1]))
  tracking_id = matches[1];
else
  exit(1, "An unexpected response was received after sending the second packet.");


# We have enough to go off of
if (
  'flex.messaging.messages.ErrorMessage' >!< res[2] &&
  'Invalid login' >!< res[2] &&
  'onResult' >< res[2] &&
  'success' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus was able to gain access using the following information :' +
      '\n' +
      '\n' + '  URL      : ' + install_url + 
      '\n' + '  User     : admin' +
      '\n' + '  Password : password' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

if (
  'flex.messaging.messages.ErrorMessage' >< res[2] &&
  'Invalid login' >< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
else exit(1, "An unexpected response was received from the web server listening on port "+port+".");
