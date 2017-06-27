#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6300) exit(0, "Nessus older than 6.3.x");

include("compat.inc");

if (description)
{
  script_id(83349);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/22 13:46:29 $");

  script_name(english:"Post-scan OS Identification");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to guess the remote operating system.");
  script_set_attribute(attribute:"description", value:
"Using a combination of remote probes (e.g. TCP/IP, SMB, HTTP, NTP,
SNMP, etc.), it was possible to guess the name of the remote operating
system in use. It was also sometimes possible to guess the version of
the operating system.

This plugin generates OS fingerprinting data used by the dashboard
feature in Nessus Manager and does not report any output of its own.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  exit(0);
}

include("agent.inc");
include("global_settings.inc");
include("misc_func.inc");

##
## Check for data populated by os_fingerprint* plugins
##
output = '';
best_score = -1;

# Dynamically makes fingerprint method list
# We only care about ones with COnfidence
methods = make_list();

OS_kbs = get_kb_list("Host/OS/*/Confidence");

if ( !isnull(OS_kbs) )
{
  foreach kb_name (keys(OS_kbs))
  {
    matches = pregmatch(pattern:"Host/OS/(\w+)/Confidence", string:kb_name);
    if (isnull(matches)) continue;

    methods = make_list(methods, matches[1]);
  }

  methods = list_uniq(methods);

  foreach meth (methods)
  {
    kb = get_kb_item("Host/OS/" + meth);
    if( kb )
    {
      score = get_kb_item("Host/OS/" + meth + "/Confidence");
      if ( isnull(score) ) continue;
      if ( score < best_score ) continue;
      best_score = score;
      best_meth  = meth;
    }
  }
}
else
  best_meth = NULL;

## Set tags from dashboard_report_host_get_tags
## /Host/Tags/report/
tag_host_ip = "";
tag_host_name = "";

if (agent())
{
  if (!empty_or_null(agent_get_ip()))
    tag_host_ip = agent_get_ip();

  if (!empty_or_null(agent_fqdn()))
  {
    tag_host_name = agent_fqdn();
    replace_kb_item(name:"myHostName", value:tag_host_name);
  }

}
else
{
  if (defined_func("get_host_ip") && get_host_ip() != NULL)
    tag_host_ip = get_host_ip();

  if (defined_func("get_host_name") && get_host_name() != NULL
      && get_host_name() != tag_host_ip)
    tag_host_name = get_host_name();
}
report_tags =
[
  ['ssh-fingerprint',   "kb",     ["Host/OS/SSH/Fingerprint"]],
  ['mac-address',       "kb",     ["Host/ifconfig/mac_addrs", "Host/mac_addrs"]],
  ['hostname',          "kb",     ["Host/hostname"]],
  ['host-fqdn',         "value",  tag_host_name],
  ['host-ip',           "value",  tag_host_ip],
  # report_xml_tag called by scan_info.nasl, no kb item set
  #['Credentialed_Scan', "kb",     ""],
  ['smb-login-used',    "kb",     ["HostLevelChecks/smb_login"]],
  ['operating-system',  "kb",     ["Host/OS/" + best_meth]]
];

foreach report_tag (report_tags)
{
  if (!get_kb_item("Host/Tags/report/" + report_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (report_tag[1] == "kb")
    {
      foreach tag_kb_item (report_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (report_tag[1] == "value")
    {
      tag_value = report_tag[2];
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      set_kb_item(name: "Host/Tags/report/" + report_tag[0], value: tag_value);
      report_xml_tag(tag:report_tag[0], value:tag_value);
    }
  }
}

## Set additional tags not in dashboard_report_host_get_tags
os_full = get_kb_item("Host/OS/" + best_meth);
tag_os = 'other';
tag_vendor = '';
tag_product = '';
tag_cpe = '';
if (strlen(os_full) && preg(pattern:"windows|microsoft", string: os_full, icase:TRUE)) {
  tag_os = 'windows';
  tag_vendor = 'microsoft';
  tag_product = 'windows';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern:"linux|unix", string: os_full, icase:TRUE)) {
  tag_os = 'linux';
  tag_vendor = 'linux';
  tag_product = 'linux_kernel';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern: "apple|mac|os_x|osx|os x|iphone|ipad", string: os_full, icase: TRUE)) {
  tag_os = 'mac';
  tag_vendor = 'apple';
  tag_product = '';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else
{
  # Generic OS + CPE Vendor/Product pairs
  # os_*[0]         os_*[1], os_*[2]
  os_linux =    ["linux",   "linux",      "linux_kernel"];
  os_windows =  ["windows", "microsoft",  "windows"];
  os_mac =      ["mac",     "apple",      "mac_os"];
  #os_mac_osx = ["mac", "apple", "mac_os_x"];
  #os_mac_server = ["mac", "apple", "mac_os_server"];
  #os_mac_x_server = ["mac", "apple", "mac_os_x_server"];
  #os_iphone = ["mac", "apple", "iphone_os"];

  kb_exists = [
    [os_linux, "Host/Linux/Distribution"]
  ];
  kb_val_match = [
    [os_linux, "LINUX", "mDNS/os"],
    [os_linux, "Linux", "Host/OS/uname"],
    [os_linux, "Archos70", "upnp/modelName"],
    [os_linux, "linux|solaris", "Services/data_protector/patch_info_is_str"],
    [os_linux, "linux|unix|Sun SNMP|hp-ux|hpux", "SNMP/sysName"],
    [os_linux, "openBSD|linux|unix|netbsd|aix|hp-ux|sco_sv", "Host/OS/ntp"],
    [os_linux, "linux|unix|Nexus [0-9]+[a-zA-Z]* Switch|Data Domain OS", "SSH/textbanner/*"],
    [os_linux, "linux|unix|netbsd|openbsd|freebsd|minix|sunos|aix|irix|dragonfly", "Host/uname"],
    [os_linux, "linux|unix|sun_ssh|freebsd|netbsd|ubuntu|debian|cisco|force10networks", "SSH/banner/*"],
    [os_linux, "linux|unix|iris|aix|minix|netbsd|openbsd|freebsd|Dell Force10|cisco|Silver Peak Systems|HP-UX|hpux", "SNMP/sysDesc"],

    [os_windows, "Service Pack ", "SMB/CSDVersion"],
    [os_windows, "Windows", "Host/OS/smb"],
    [os_windows, "Windows", "Host/Veritas/BackupExecAgent/OS_Version"],
    [os_windows, "Windows ", "SMB/ProductName"],
    [os_windows, "Windows ", "upnp/modelName"],
    [os_windows, "microsoft", "Services/data_protector/patch_info_is_str"],
    [os_windows, "microsoft|windows", "SNMP/sysName"],
    [os_windows, "microsoft|windows", "Host/OS/ntp"],

    [os_mac, "AFP[X23]", "Host/OS/AFP/fingerprint"],
    [os_mac, "apple|darwin", "SNMP/sysDesc"],
    [os_mac, "darwin", "Host/uname"],
    [os_mac, "Mac OS X", "mDNS/os"],
    [os_mac, "cygwin|mingw32", "Host/uname"],
    [os_mac, "Darwin Kernel Release", "SNMP/sysName"],
    [os_mac, "(Darwin).*(x86_64|i386)", "Host/OS/ntp"]
  ];

  foreach kbitem (kb_exists)
  {
    if (get_kb_item(kbitem[1]))
    {
      os_info = kbitem[0];
      tag_os = os_info[0];
      tag_vendor = os_info[1];
      tag_product = os_info[2];
      tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
      break;
    }
  }

  foreach kbitem (kb_val_match)
  {
    if (tag_cpe != '') break;
    kblist = get_kb_list(kbitem[2]);
    foreach kbkey (keys(kblist))
    {
      kbval = kblist[kbkey];
      if (preg(pattern: kbitem[1], string: kbval, icase: TRUE))
      {
        os_info = kbitem[0];
        tag_os = os_info[0];
        tag_vendor = os_info[1];
        tag_product = os_info[2];
        tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
        break;
      }
    }
  }
}

addl_tags =
[
  ['os',            "value",  tag_os],
  ['cpe',           "value",  tag_cpe]
  #['id',            "value",  ""],
  #['is_new',        "value",  ""],
  #['is_auth',       "value",  ""],
  #['scan_type',     "value",  ""],
  #['severity',      "value",  ""],
  #['severitycount', "value",  ""],
  #['last_update',   "value",  ""],
  #['host_index',    "value",  ""]
];

foreach addl_tag (addl_tags)
{
  if (!get_kb_item("Host/Tags/report/" + addl_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (addl_tag[1] == "kb")
    {
      foreach tag_kb_item (addl_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (addl_tag[1] == "value")
    {
      tag_value = addl_tag[2];
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      set_kb_item(name: "Host/Tags/" + addl_tag[0], value: tag_value);
      report_xml_tag(tag:addl_tag[0], value:tag_value);
    }
  }
}

function build_cpe_from_tags(type, vendor, product)
{
  local_var cpe_string;
  cpe_string = 'cpe:/';
  if (type != '')
  {
    cpe_string += type;
    if (vendor != '')
    {
      cpe_string += ':'+vendor;
      if (product != '')
      {
        cpe_string += ':'+product;
      }
    }
  }
  return cpe_string;
}
