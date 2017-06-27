#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50514);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/09 22:45:48 $");

  script_name(english:"Novatel MiFi Default Credentials");
  script_summary(english:"Tries to login with default credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote MiFi device has its default administrative password set.");
 script_set_attribute(attribute:"description", value:
"The remote host is a Novatel MiFi device, a portable access point
using 3G/EVDO to connect to the Internet. 

The remote device is using the default password ('admin') for
administrative access.  This may allow anyone on this network to log
into the device and force it to connect/disconnect from the
network.");

  script_set_attribute(attribute:"solution", value:
"Log into the remote device and change the password to a stronger one");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/08");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("vzw_novatel_mifi_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("Host/novatel_mifi_device");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
installed = get_kb_item_or_exit("Host/novatel_mifi_device");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/",
  exit_on_fail : TRUE
);
token = egrep(pattern:'var pwtoken = "[^"]+";', string:res[2]);
if (!token) exit(0, "Nessus was unable to obtain the required token on port " + port);

token = chomp(ereg_replace(pattern:'var pwtoken = "([^"]+)";', string:token, replace:"\1"));
stoken = egrep(pattern:'<input type="hidden" name="stoken" value="[^"]+">', string:res[2]);

if (!stoken) exit(0, "Nessus was unable to obtain the required token on port " + port);

stoken = chomp(ereg_replace(pattern:'<input type="hidden" name="stoken" value="([^"]+)">', string:stoken, replace:"\1"));
pass = hexstr(SHA1("admin" + token));

data = "buttonlogin=Login&AdPassword=" + pass + "&todo=login&nextfile=home.html&stoken=" + stoken;

res = http_send_recv3(
  method : "POST",
  port   : port,
  data   : data,
  item   : "/login.cgi",
  add_headers : make_array("Origin", "http://" + get_host_ip(), "Referer", "http://" + get_host_ip() + "/"),
  content_type : 'application/x-www-form-urlencoded',
  exit_on_fail : TRUE
);

if ( 'function setWan()\r
{\r
var cf = self.document.forms[0];\r
var cb = cf.elements["connectDisconnect"];\r
if (cb.value == text_connect )\r
{\r
cf.elements["todo"].value = "connect";\r
cf.submit();\r
}\r' >< res[2])
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to gain access using the following information :\n' +
      '\n' +
      '  URL      : ' + install_url +
      '  User     : admin' + '\n' +
      '  Password : ' + pass + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
