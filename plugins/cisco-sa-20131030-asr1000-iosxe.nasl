#TRUSTED 3f3465189fbc567b9ceb10b5012828d2fafbe497c6a6c4d8b2615a434410bb6dfadd84776b7aefcb17870eb3786f4413c9a92e5776ce708f4cbf8f9cade3fd2dd25dc9d443cfcd399395b013a9fa323953d481b52ed97bec93f5e097aa2f0786cd899e55d5c26a9a2751a70242880b6c0e91b24f730bedde4bd0da08c8e8cee98b3d0e8d07be0eee76091db22f97980b320bf7b447436b106b003ac0141efa6e946e10f4c3ecbcfb72e9b007e35d2873ac2e4272c8df3a81fd166018062752c1d5655876b21eac8a6a515f95effdfb37e5cbf14b0114adf7f5daea3350203d079fafc304d97b967494106187249d476c197f6084c4691e2666203d02ba3c66c8f1cfc79ae036cf09ac29e644102cc8d34c96ba9afed38991bf29f4015eabe3a6c926bf579cba9d886f6d9d8e373b50f824a12a3b5d9012fc9c9225837f551920247c054d61fef5f86a75869dec9826708d3a07b4374195bfdca33079696ec30bfee8785ce0f1c6e70429571330bf4dd3eb211b4b4e93aa58cec1f2256179841d48dfdbc09b5bce36643c01426a92b8c01720375fd4e4f2be38cd734dd36316091baac2291374a7f0f11d3fd2f60d132ee54964e1647530e4d230c2dd9ce8be030f912f4191f3e199896448cee025cb6a173e2688547a73667fa221f7b1704556027ba5f23b649811b9cbd2bfdb22d85428935296860995d966b1f6caf777c28f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70784);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/12/19");

  script_cve_id(
    "CVE-2013-5543",
    "CVE-2013-5545",
    "CVE-2013-5546",
    "CVE-2013-5547"
  );
  script_bugtraq_id(63436, 63439, 63443, 63444);
  script_osvdb_id(99152, 99153, 99154, 99155);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt26470");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud72509");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf08269");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh19936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131030-asr1000");

  script_name(english:"Multiple Vulnerabilities in Cisco IOS XE Software for 1000 Series Aggregation Services Routers (cisco-sa-20131030-asr1000)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cisco IOS XE Software for 1000 Series Aggregation Services Routers
(ASR) contains the following denial of service (DoS) vulnerabilities :

  - Cisco IOS XE Software TCP Segment Reassembly Denial of
    Service Vulnerability (CVE-2013-5543)

  - Cisco IOS XE Software Malformed EoGRE Packet Denial of
    Service Vulnerability (CVE-2013-5545)

  - Cisco IOS XE Software Malformed ICMP Packet Denial of
    Service Vulnerability (CVE-2013-5546)

  - Cisco IOS XE Software PPTP Traffic Denial of Service
    Vulnerability (CVE-2013-5547)

These vulnerabilities are independent of each other. A release that is
affected by one of the vulnerabilities may not be affected by the
others.

Successful exploitation of any of these vulnerabilities allows an
unauthenticated, remote attacker to trigger a reload of the Embedded
Services Processors (ESP) card or the Route Processor (RP) card, which
causes an interruption of services.

Repeated exploitation can result in a sustained DoS condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131030-asr1000
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be931de5");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131030-asr1000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/07");

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
cbi = "CSCtt26470";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.4[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.4.2S') == -1)) { fixed_ver = "3.4.2S"; temp_flag++; }
if ((version =~ '^3\\.5[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.5.1S') == -1)) { fixed_ver = "3.5.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_type_inspect_zone-pair", "show policy-map type inspect zone-pair");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"Match: protocol udp", string:buf)) ||
             (preg(multiline:TRUE, pattern:"Match: protocol tcp", string:buf))
            ) &&
           (preg(multiline:TRUE, pattern:"Inspect", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCuh19936";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
           (
             (preg(multiline:TRUE, pattern:"ip nat inside", string:buf)) ||
             (preg(multiline:TRUE, pattern:"ip nat outside", string:buf))
            ) &&
           (!preg(multiline:TRUE, pattern:"no ip nat service pptp", string:buf))
         ) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCud72509";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.7[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.7.3S') == -1)) { fixed_ver = "3.7.3S"; temp_flag++; }
if ((version =~ '^3\\.8[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.8.1S') == -1)) { fixed_ver = "3.8.1S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"ip nat (inside|outside)", string:buf))
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_inventory", "show inventory");
        if (check_cisco_result(buf))
        {
          if (preg(multiline:TRUE, pattern:"ASR1000-ESP100", string:buf)) { temp_flag = 1; }
          if (preg(multiline:TRUE, pattern:"ASR1002-X", string:buf)) { temp_flag = 1; }
        } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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

cbi = "CSCuf08269";
fixed_ver = "";
temp_flag = 0;
if ((version =~ '^3\\.9[^0-9]') && (cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) { fixed_ver = "3.9.2S"; temp_flag++; }

if (get_kb_item("Host/local_checks_enabled"))
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv4", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"tunnel mode ethernet gre ipv6", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
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
  security_hole(port:0, extra:cisco_caveat());
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
