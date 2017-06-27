#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62990);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_osvdb_id(87336);
  script_xref(name:"EDB-ID", value:"22737");

  script_name(english:"NetIQ Privileged User Manager Default Admin Password");
  script_summary(english:"Tries to login using default password");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is protected by
known default credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the NetIQ Privileged User Manager install
running on the remote host using default, known credentials for the
'admin' user.");
  script_set_attribute(attribute:"solution", value:"Change the default 'admin' password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:privileged_user_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("netiq_pum_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("global_settings/supplied_logins_only", "Settings/disable_cgi_scanning");
  script_require_keys("www/netiq_pum");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# app runs on port 443 by default, but can be configured to run on port 80
port = get_http_port(default:443);

appname = "NetIQ Privileged User Manager";
kb_appname = "netiq_pum";

install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:TRUE);
dir = install['dir'];

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

admin_password = "novell";

# Login
# AMF encoded data
postdata=
  raw_string(0x00,0x00,0x00,0x00,0x00,0x01,
             0x00,0x15) + # len
  "SPF.Util.callModuleEx" + 
  raw_string(0x00,0x02,0x2f,0x34,0x00,0x00,0x00,0x65,0x0a,0x00,0x00,0x00,0x01,
             0x03, # obj
             0x00,0x03) + # len
  "pkt" +
  raw_string(0x03, # obj
             0x00,0x0b) + # len
  "Credentials" +
  raw_string(0x03, # obj
             0x00, 0x04) + # len
  "name" + 
  raw_string(0x02, # str 
             0x00,0x05) + # len
  "admin" + 
  raw_string(0x00,0x06) + # len
  "passwd" +
  raw_string(0x02) + # str
  mkword(strlen(admin_password)) +
  admin_password +
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x06) + # len
  "method" +  
  raw_string(0x02, # str
             0x00,0x05) + # len
  "login" +
  raw_string(0x00,0x06) + # len
  "module" +
  raw_string(0x02, # str
             0x00,0x04) + # len
  "auth" +
  raw_string(0x00,0x03) + # len
  "uid" +
  raw_string(0x06,
             0x00,0x00,0x09, # end obj
             0x00,0x00,0x09); # end obj

res = http_send_recv3(
  method:'POST',
  item: dir + '/',
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '11,4,402,278'
  ),
  data:postdata, 
  exit_on_fail:TRUE
);

# try to parse out login message
msg = NULL;
msg_search = raw_string(
               0x00, 0x07, # length
               0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, # "message"
               0x02 # string is next
             );

pos = stridx(res[2], msg_search);

if (msg_search >< res[2] && pos >= 0)
{
  len = getword(blob:res[2], pos: pos + strlen(msg_search));
  if (len == NULL) exit(1, "The response from port "+port+" is not long enough to contain the length of message string.");

  if (strlen(res[2]) <  pos + strlen(msg_search) + 2 + len) exit(1, "The response from port "+port+" is not long enough to contain message string.");

  msg = substr(res[2], pos + strlen(msg_search) + 2, pos + strlen(msg_search) + 2 + len - 1);  
}

if (
  !isnull(msg) &&
  (
    'successfully authenticated' >< msg ||
    'Password has expired' >< msg
  ) &&
  'Invalid user name or password' >!< msg
)
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to login using default credentials for the \'admin\' user : \n\n' +
    '  Password : ' + admin_password + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:dir, port:port));
