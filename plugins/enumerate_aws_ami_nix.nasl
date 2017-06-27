#TRUSTED 352a8711128d7e4f39981ccfd86e1c188fee7dc886473bca62ef0d97c175907fb512c909295cdb02b1fc4affde1d8e8300f5168b8f5b9c9731b75e0f611b2d46a81314d3b5c5a4431c26d244eb4c78b80822ba934f09b963447db5b86286f54b71fe957594baa1cf0c3a4b4ddb613a50907e985ae9ccffe106d55e19ec12868c295dcf1e124a09b1860a71130b8a64ddd4d4d461ea793feb58ba4ecc1f984e6ed5d4072d1434da17684d04faf30b126fbfee19e3c19317eabe759ab5e1ed9b1855eda5086f3584a73ad751b0cdb81d4ebc37bd59547e4f92592c0796b800f3affd2111a07aa30c4356a9759d697a62e79ca9e216b9b8f386e523459cb3437adfb95148c2d35c4f31d364a9bf6991935200921887486002efe6dee7f5191404fa8a606c3ab7347d5ee4590e90e3e2b9c94d348caa9964a4d1f23f029d3999e8f2afcedf12e258e3c3b8a4045b3763b8c0abde8648c3807943394ceec95a84873498d55d7823c8ee4edf70000bff21157bff743c87ff197da0aadd75375f75dbe1749d5ea2be92d07b2952afccb8eb177329a6c3e8b0e7b9af106b740f9913847291f42ddd725c7ad8d48050c719131dbfc062e46ee72615fcdc7fb8054a8be99ddecad1976d66dec7f5046722c5ea8883fcf8656f1e4531cadd7c408b8e64076aa9b6de08ef7318a9d6c409dcf056c028a3c00740d6cc44489c6a4e1ea37464c9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90191);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_name(english:"Amazon Web Services EC2 Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve EC2 metadata from a Unix like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an AWS EC2 instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be an Amazon Machine Image. Nessus was able
to use the metadata API to collect information about the system.");
  script_set_attribute(attribute:"see_also", value:"https://aws.amazon.com/documentation/ec2/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("http.inc");
# Include global constants for interacting with the API
include("amazon_aws_ami.inc");

global_var info_t = NULL;

###
# Establish transport for command running
#
# @remark Checks a list of "supported OS" kb items, and will
#         exit / audit on any failure that would not allow 
#         us to continue the check.
#
# @return Always NULL
###
function init_trans()
{
  local_var unsupported, supported, oskb;

  get_kb_item_or_exit("Host/local_checks_enabled");

  unsupported = TRUE;
  # Remote OSes this check is supported on, should this only
  # be Host/AmazonLinux/release ?
  supported = make_list(
    "Host/AmazonLinux/release",
    "Host/CentOS/release",
    "Host/Debian/release",
    "Host/FreeBSD/release",
    "Host/Gentoo/release",
    "Host/HP-UX/version",
    "Host/Mandrake/release",
    "Host/RedHat/release",
    "Host/Slackware/release",
    "Host/Solaris/Version",
    "Host/Solaris11/Version",
    "Host/SuSE/release",
    "Host/Ubuntu/release",
    "Host/AIX/version"
  );

  foreach oskb (supported)
  {
    if(get_kb_item(oskb))
    {
      unsupported = FALSE;
      break;
    }
  }

  # Not a support OS, bail
  if (unsupported)
    exit(0, "Collection of AWS metadata via this plugin is not supported on the host.");

  # Establish command transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      audit(AUDIT_FN_UNDEF,"pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL,"ssh_open_connection");
    info_t = INFO_SSH;
  }
}

###
# Logging wrapper for info_send_command
#
# @param cmd string command to run with info send command
#
# @return the output of the command
###
function run_cmd(cmd)
{
  local_var ret;
  spad_log(message:'Running command :\n'+cmd);
  ret = info_send_cmd(cmd:cmd);
  spad_log(message:'Output :\n'+ret);
  return ret;
}

##
# Checks the BIOS/Hypervisor info for an Amazon BIOS/version of Xen
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function amazon_bios_check()
{
  local_var pbuf;
  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/bios_version');
  if ("amazon" >< pbuf) return TRUE;
  pbuf = run_cmd(cmd:'dmidecode -s system-version 2>&1');
  if ("amazon" >< pbuf) return TRUE;

  # Paravirtualized AMIs
  pbuf = run_cmd(cmd:'cat /sys/hypervisor/version/extra');
  if ("amazon" >< pbuf) return TRUE;
  else return FALSE;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  local_var item, cmd, cmdt;
  cmdt = "wget -q -O - {URI}";
  item = "http://"+AWS_AMI_API_HOST+AWS_AMI_API_ROOT;
  if(!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  cmd = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For remote scans / agent scans
##
function use_curl()
{
  local_var item, cmd, cmdt;
  cmdt = "curl -s {URI}";
  item = "http://"+AWS_AMI_API_HOST+AWS_AMI_API_ROOT;
  if(!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  cmd  = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  local_var item, ret;
  item = AWS_AMI_API_ROOT;
  if(!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  ret = http_send_recv3(
    target       : AWS_AMI_API_HOST,
    item         : item,
    port         : 80,
    method       : "GET",
    exit_on_fail : FALSE
  );
  # Return response body
  if (!empty_or_null(ret))
    return ret[2];
  return NULL;
}

###
# Choose the function we will use to get API data with
#
# @remark The agent must run curl / wget to retrieve these 
#         items, plugins run by the agent are not allowed to
#         open any sockets.
#
# @return FALSE when no suitable method of calling the API can be found
#         A function pointer for one of the use_* functions defined above
##
function choose_api_function()
{
  local_var pbuf;
  if (info_t == INFO_LOCAL && !get_kb_item("nessus/product/agent"))
    return @use_send_recv3;
  else
  {
    # We prefer cURL over wget
    pbuf = run_cmd(cmd:'curl --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'curl --help' >< pbuf)
      return @use_curl;
    pbuf = run_cmd(cmd:'wget --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'wget --help' >< pbuf)
      return @use_wget;
  }
  return FALSE;
}

# Initialize command transport and determine how to talk to the API
init_trans();

if (!amazon_bios_check())
  exit(0,"BIOS and Hypervisor information indicate the system is likely not an AWS Instance.");

api_get_item = choose_api_function();
if (!api_get_item)
  exit(1, "There are no suitable methods for retrieving AMI data on the system.");

# Knowledge and xml tag bases
kbbase = AWS_AMI_KB_BASE;
xtbase = AWS_AMI_HOST_TAG_BASE;

# API items we want to get and their validation regexes
apitems = AWS_AMI_API_ITEMS;

# Check the API root first
buf = api_get_item();
if (isnull(buf) || "ami-id" >!< buf || "instance-id" >!< buf)
  exit(1,"The remote host does not appear to be an AWS Instance.");

# Now get each item we're interested in and validate them
success = make_list();
failure = make_list();
foreach apitem (keys(apitems))
{
  buf = api_get_item(apitem);
  rgx = apitems[apitem];

  if (empty_or_null(buf) || buf !~ rgx)
    failure = make_list(failure, apitem);
  else
  {
    replace_kb_item(name:kbbase+"/"+apitem, value:buf);
    report_xml_tag(tag:xtbase+"-"+apitem, value:buf);
    success = make_list(success, apitem);
  }
}

# Report successful retrievals
report = "";
if (max_index(success) != 0)
{
  report += 
  '\n  It was possible to retrieve the following API items :\n';
  foreach apitem (success)
    report += '\n    - '+apitem;
  report += '\n';
}

# Report failures, should always be blank, mostly to help out CS
if (max_index(failure) != 0)
{
  report += 
  '\n  The following items could not be retrieved :\n';
  foreach apitem (failure)
    report += '\n    - '+apitem;
  report += '\n';
}

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
