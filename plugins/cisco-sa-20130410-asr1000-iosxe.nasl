#TRUSTED 1097c7e996595414d525609ae8959d395c2cedb57ce7f19eaf75caef5608d96b7074f3c60d04ff7ade2fd1cce92cc7e8128bd00d841db22ef7f60bbf7c507b1492ced065f7742ce82dead59e04c252192a48abc238284fbdc3e92ff0cd7d48561e96e925d3a278c18f355d221d78bd1efdc34b1f58c28fd0ac35a540276b1721817126b16835a8a44d86ebecd0a39c453e079cec3ca39eaf687e7e5ab194cefff0a1c89d3d639992804b1e4aee7e32c16de5f704b39411f5a1f5c0de2e65f0eee4bde9352d2c952295c8be1c7795b2ee1e8b5bc036b66944476b25f74e7655b7ba644d9ca29a3914298fc34669a701925530a3bc539722115a11571b5a1386d7d1c906d927d9db2f6bd180e719ea9bd6cd24548790dfa08a1ef3030122384c573d578d9b17fee3b3b7121ddab7a27e57ed699aa8c11442c8f0c18ce77900bf692959d12536c831310c30300891310d4ccca3e35a5c3f7309b9c25b0f31b6544f5187b71479fdfb8ff1d401ab0cd503566ee6ad2d2bc22ba6cf1a9633b05e72c7d5c9a8b12b0285e63c033e2a155ca6eebbe46115dde6eb3910faef50af0c1ec5ca352abc66910e6ca6a2d7f34dfefc30a064c5a1c360321b7817258959e2860cdf91b4eca5a20af34bd7121fdff2cacdfe1b7207bc82c350ee6a68d35d15bf5e7f94c0ff472d404aa35a2b1e7913cfbbf7aad4bf63d84ff9608880a1e7704359
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67218);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/19");

  script_cve_id(
    "CVE-2013-1164",
    "CVE-2013-1165",
    "CVE-2013-1166",
    "CVE-2013-1167",
    "CVE-2013-2779"
  );
  script_bugtraq_id(59003, 59007, 59008, 59009, 59040);
  script_osvdb_id(92203, 92204, 92205, 92206, 92207);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz97563");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub34945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz23293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc65609");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt11558");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20130410-asr1000)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software IPv6 Multicast Traffic Denial of
    Service Vulnerability (CVE-2013-1164)

  - Cisco IOS XE Software L2TP Traffic Denial of Service
    Vulnerability (CVE-2013-1165)

  - Cisco IOS XE Software SIP Traffic Denial of Service
    Vulnerability (CVE-2013-1166)

  - Cisco IOS XE Software Bridge Domain Interface Denial of
    Service Vulnerability (CVE-2013-1167)

  - Cisco IOS XE Software MVPNv6 Traffic Denial of Service
    Vulnerability (CVE-2013-2779)

These vulnerabilities are independent of each other, meaning that a
release that is affected by one of the vulnerabilities may not be
affected by the others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card,
causing an interruption of services.

Repeated exploitation could result in a sustained DoS condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c363bc5");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extras = "";
override = 0;
model = "";

# check hardware
if (get_kb_item("Host/local_checks_enabled"))
{
  # this advisory only addresses CISCO ASR 1000 series
  buf = cisco_command_kb_item("Host/Cisco/Config/show_platform", "show platform");
  if (buf)
  {
    match = eregmatch(pattern:"Chassis type:\s+ASR([^ ]+)", string:buf);
    if (!isnull(match)) model = match[1];
  }
}
if (model !~ '^10[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# for each cisco bug id, check version and then individual additional checks
# --------------------------------------------
# Cisco IOS XE Software IPv6 Multicast Traffic Denial of Service Vulnerability
# Cisco IOS XE Software MVPNv6 Traffic Denial of Service Vulnerability

cbi = "CSCtz97563 and CSCub34945";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipv6", "show running | include ipv6.(enable|address)");
    if (check_cisco_result(buf))
    {
      if ( (preg(multiline:TRUE, pattern:"ipv6 enable", string:buf)) && (preg(multiline:TRUE, pattern:"ipv6 address", string:buf)) ) { temp_flag = 1; }
	  if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP40", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software L2TP Traffic Denial of Service Vulnerability

cbi = "CSCtz23293";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.1[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.5S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.6[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.1S') == -1)) { fixed_ver = "3.7.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_accept-dialin", "show running | include accept-dialin");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"accept-dialin", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	  	temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_xconnect_l2tpv3", "show running | include xconnect|l2tpv3");
        if (check_cisco_result(buf))
        {
          if ( (preg(multiline:TRUE, pattern:"encapsulation l2tpv3", string:buf)) && (preg(multiline:TRUE, pattern:"xconnect", string:buf)) ) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software Bridge Domain Interface Denial of Service Vulnerability

cbi = "CSCtt11558";
fixed_ver = "";
temp_flag = 0;
if (version =~ '^3\\.2[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if (version =~ '^3\\.3[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if (version =~ '^3\\.5[^0-9]') { fixed_ver = "migrate to an appropriate extended release"; temp_flag++; }

# this check may result in a False Positive condition
# as it would be impossible to create a check that handles
# 100% of configurations, this is a best effort approach
if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_interface", "show running | section interface");
    if (check_cisco_result(buf))
    {
        if (
             (preg(multiline:TRUE, pattern:"interface[^!]*encapsulation untagged", string:buf)) &&
             (preg(multiline:TRUE, pattern:"interface BDI", string:buf)) &&
             (preg(multiline:TRUE, pattern:"rewrite egress", string:buf)) ) { flag = 1; }
        { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------
# Cisco IOS XE Software SIP Traffic Denial of Service Vulnerability

cbi = "CSCuc65609";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.5S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_include_ipnatvrf", "show running-config  | include ip (nat | .* vrf .*)");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+inside", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"\s+ip\s+nat\s+outside", string:buf)) { temp_flag = 1; }
      if (temp_flag)
      {
	    temp_flag = 0;
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running_include_ipnat", "show running | include ip nat");
        if (check_cisco_result(buf))
        {
          if (!preg(multiline:TRUE, pattern:"no ip nat service sip", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# --------------------------------------------

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
