#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69081);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/24 22:49:06 $");

  script_name(english:"Cisco Web Security Appliance Version");
  script_summary(english:"Tries to get the WSA version via HTTP and SSH.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the version of the remote appliance.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Cisco Web Security Appliance (WSA), a web
gateway security appliance.

It is possible to get the WSA version number via SSH or HTTP.");
  # http://www.cisco.com/c/en/us/products/security/web-security-appliance/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f99d1f7");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "cisco_wsa_web_detect.nasl");
  script_require_ports("Host/AsyncOS/Cisco Web Security Appliance", "www/cisco_wsa");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("webapp_func.inc");

##
# Saves the provided WSA version number in the KB, generates plugin output,
# and exits.  If a model is provided it is also saved in the KB and reported,
# but a model is not required.
#
# @anonparam ver WSA version number
# @anonparam model WSA version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source)
{
  local_var report, display_ver, host;

  # versions look like w.x.y-z (includes a dash)
  # in order to allow them to be used easily with existing functions (namely ver_compare()),
  # they will also be converted to and saved in the kb as w.x.y.z (no dash)
  display_ver = ver;
  ver = str_replace(string:ver, find:'-', replace:'.');
  set_kb_item(name:"Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", value:display_ver);
  set_kb_item(name:"Host/AsyncOS/Cisco Web Security Appliance/Version", value:ver);


  host = "AsyncOS " + display_ver + " on Cisco Web Security Appliance";
  if (!isnull(model))
  {
    host = host + " " + model;
    set_kb_item(name:"Host/AsyncOS/Cisco Web Security Appliance/Model", value:model);
  }

  set_kb_item(name:"Host/OS/AsyncOS", value:host);
  set_kb_item(name:"Host/OS/AsyncOS/Type", value:"general-purpose");
  set_kb_item(name:"Host/OS/AsyncOS/Confidence", value:100);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + display_ver;
    if (!isnull(model))
      report += '\n  Model : ' + model;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
wsa_ssh = get_kb_item("Host/AsyncOS/Cisco Web Security Appliance");
ver_cmd = get_kb_item("Host/AsyncOS/version_cmd");
if (wsa_ssh && !isnull(ver_cmd))
{
  model = eregmatch(string:ver_cmd, pattern:'Model: (.+)');
  version = eregmatch(string:ver_cmd, pattern:'Version: ([0-9.-]+)');

  if (!isnull(version))
  {
    report_and_exit(ver:version[1], model:model[1], source:'SSH');
    # never reached
  }
}

# 2. HTTP
ports = get_kb_list('Services/www'); # forking is unlikely, but it will be avoided anyway

foreach port (ports)
{
  install = get_install_from_kb(appname:'cisco_wsa', port:port);
  if (isnull(install)) continue;
  wsa_http = TRUE;

  ver = install['ver'];
  if (ver == UNKNOWN_VER) continue;

  model = get_kb_item('cisco_wsa/' + port + '/model');
  report_and_exit(ver:ver, model:model, source:'HTTP');
  # never reached
}

failed_methods = make_list();
if (wsa_ssh)
  failed_methods = make_list(failed_methods, 'SSH');
if (wsa_http)
  failed_methods = make_list(failed_methods, 'HTTP');

if (max_index(failed_methods) > 0)
  exit(1, 'Unable to determine WSA version number obtained via ' + join(failed_methods, sep:'/') + '.');
else
  exit(0, 'The WSA version is not available (the remote host may not be WSA).');
