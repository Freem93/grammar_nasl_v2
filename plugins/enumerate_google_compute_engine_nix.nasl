#TRUSTED 1d272200c8caa241066787575df01e75dd9016b0f016053aac5557ebb3d0c560572828b491af50ab16c7548a225dfcf93eff6847ceaf66565fc73cc4d8b7bed105fc6c05f846e2ec35f0f4040aad899dde7771b99924a496edb6b2cf2ea462eaed0d2c89dc236df5847f581622ca0303ff5471e6f836316a19e6f62e5b7006cf029eb355b44e85a7625521e7ca0b12629df5c9a53f137079370fc3b58255f785341e2fd76fce01975a90a25af01c2a04659b158d55fde89d67c7c53bd288e086a53371a42b0f1dafa5e3e7933e2a5a2f88a469957b0ab330bb04d584119d5ef8d356b47630faec4365ff6ccf47e9b2e44cb649bcc0857c93bf3eb81a5e001a5a845decbc93e64bb14f464456948392090df83db004ddc13c760e6441c5ee159c223ff439d7ee3fd9e8d532fc53a52df06881586dfe26153c097c65ec9cc52b5a8d745dde0b62dbcd82c6cc035ee45f1402e9240c38a838dea652a7a5b26a0a37bdef8dcaab5ac0c16106f197604d530d32e60057a7c5915bd61f8a21ed1929c284b8e9338af580e90e98b9c8090f9a3723baa874fe74fbc5c6fd633decd0ae0eab5bbce9f5f347d1a3f96521d38030b18d7fa3f24bd6987861bc01bebfbda39a94ec0290aace61173e03d677bdc92b593512c85431adf8d3a36d1ebad382140af47a19b816afed147228b34f3054dcd8b1505600dcc043cc4415eb7c13a70e09
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99169);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/03");

  script_name(english:"Google Cloud Platform Compute Engine Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve Google Compute Engine metadata from a Unix-like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a Google Compute Engine instance for which metadata
could be retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Google Compute Engine instance. Nessus
was able to use the metadata API to collect information about the
system.");
  script_set_attribute(attribute:"see_also", value:"https://cloud.google.com/compute/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:compute_engine");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
include("google_compute_engine.inc");

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
  # Remote OSes this check is supported on
  supported = make_list(
    "Host/Debian/release",
    "Host/CentOS/release",
    "Host/Ubuntu/release",
    "Host/RedHat/release",
    "Host/SuSE/release",
    "Host/Container-Optimized OS/release"
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
    exit(0, "Collection of Google Compute Engine metadata via this plugin is not supported on the host.");

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
# Checks the BIOS/Hypervisor info for Google Compute Engine
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function google_compute_engine_bios_check()
{
  local_var pbuf;
  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/product_name');
  if ("Google Compute Engine" >< pbuf) return TRUE;
  else return FALSE;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  local_var item, cmd, cmdt;
  cmdt = 'wget --header="Metadata-Flavor: Google" -q -O - {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
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
  cmdt = 'curl --header "Metadata-Flavor: Google" -s {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
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
  item = GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if(!empty_or_null(_FCT_ANON_ARGS[0]))
    item += _FCT_ANON_ARGS[0];
  ret = http_send_recv3(
    target       : GOOGLE_COMPUTE_ENGINE_API_HOST,
    item         : item,
    port         : 80,
    method       : "GET",
    add_headers  : make_array("Metadata-Flavor", "Google"),
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

if (!google_compute_engine_bios_check())
  exit(0,"BIOS information indicates the system is likely not a Google Compute Engine instance.");

api_get_item = choose_api_function();
if (!api_get_item)
  exit(1, "There are no suitable methods for retrieving Google Compute Engine metadata on the system.");

# Knowledge and xml tag bases
kbbase = GOOGLE_COMPUTE_ENGINE_KB_BASE;
xtbase = GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE;

# API items we want to get and their validation regexes
apitems = GOOGLE_COMPUTE_ENGINE_API_ITEMS;

# Check the API root first
buf = api_get_item();
if (isnull(buf) || "hostname" >!< buf || "network-interfaces/" >!< buf)
  exit(1,"The remote host does not appear to be a Google Compute Engine instance.");

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
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:buf);
    success = make_list(success, apitem);
  }
}

# For grabbing IP addresses. X and Y are indexes.
# Internals are at /network-interfaces/X/ip
# Externals are at /network-interfaces/X/access-configs/Y/external-ip
# GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST = "network-interfaces/";
# GOOGLE_COMPUTE_ENGINE_IP = "ip";
# GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST = "access-configs/";
# GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP = "external-ip";
network_interfaces = api_get_item(GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST);
foreach interface (split(network_interfaces, keep:FALSE))
{
  # interface = "0/"

  # first grab internal ip
  # don't log failures, as this interface may not have an internal ip
  apitem = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST + interface + "ip";
  internal_ip = api_get_item(apitem);
  if (!empty_or_null(internal_ip) && internal_ip =~ "^\d+\.\d+\.\d+\.\d+$")
  {
    replace_kb_item(name:kbbase+"/"+apitem, value:internal_ip);
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:internal_ip);
    success = make_list(success, apitem);
  }

  # then try enumerating external ips
  access_configs = api_get_item(
    GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
    interface +
    GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST
  );
  foreach config (split(access_configs, keep:FALSE))
  {
    apitem  = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
              interface +
              GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST +
              config +
              "external-ip";
    external_ip = api_get_item(apitem);
    if (!empty_or_null(external_ip) && external_ip =~ "^\d+\.\d+\.\d+\.\d+$")
    {
      replace_kb_item(name:kbbase+"/"+apitem, value:external_ip);
      apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
      report_xml_tag(tag:xtbase+"-"+apitem_tag, value:external_ip);
      success = make_list(success, apitem);
    }
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
