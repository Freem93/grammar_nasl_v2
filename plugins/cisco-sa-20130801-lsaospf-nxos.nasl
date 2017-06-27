#TRUSTED a52a1461bbd45a50bc436f61d0b8bd6cfdaae556a2f8ddbbd2f0d56d6d2dfab5ffa6a8bef10ccb8d7d431eed20645c99a749ff0e510b9e21f27c84d754106e6f8ae858fe358c5e294aee7d2e924e40d9464b5f746ab7ab04cfc3797fb73af0eb029d9c9c7a57a48e26e0ebcbbc63c074feb6bb42cb3dde8e5eb22ce750532741fcf0e9cbcc5cf30980eb6b9de4b904a802f19c66bc4903fef86e4411def5d7f9cdfb559b80cc0db027d86a6740937ac9963a5a62d8053d6ec0778baa2b01250094856f40b4f098e7ca648d60a6490304ff88aac0d65313a0115a886c992e7d280811bb5ef8c183661f790415c4ce2a7879b67224db402be69aa1c50ac5deed35f672c2b081c6db0804a4ce7ad4457f21c82bf5a88018e228ebaf1750a2fb2ea998a6e8f889cfb5b49010985d3408396dacb00a24649b4767747b2ca38b53fcc08fdd934ce5cabcf14fafede4b864204de59e67162640d179715231ba1c425d99571ab7f595be92526e5789fb7b15486650f5d2035428d07be2c9cb4f09a87e631e84f2542f4098065aaa2d7f41e2cf7530a067526840767c89c73df06f641abde27eac0681195b19dddc51ae8883cca65b6b23ad791b18e4c028506ff588dde90e3a9a23870346850e65a18e7f12e95e0f064d41f7031f27c4dc5c20c2352cfc777c5617456bd04aa88a63594a9a4a0a16658d91682bab3554f1e7cfa90b13ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69379);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/13");

  script_cve_id("CVE-2013-0149");
  script_bugtraq_id(61566);
  script_osvdb_id(109017);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug63304");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130801-lsaospf");

  script_name(english:"OSPF LSA Manipulation Vulnerability in Cisco NX-OS (cisco-sa-20130801-lsaospf)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco NX-OS device is affected by a vulnerability involving
the Open Shortest Path First (OSPF) routing protocol Link State
Advertisement (LSA) database. By injecting specially crafted OSPF
packets, an unauthenticated attacker could manipulate or disrupt the
flow of network traffic through the device.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130801-lsaospf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58c1354a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130801-lsaospf.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
device = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

if (device != 'Nexus') audit(AUDIT_HOST_NOT, "affected");

if (model =~ "^1000[Vv]$") audit(AUDIT_HOST_NOT, "affected");

flag = 0;
override = 0;

# Affected versions as of: 7/31/14
# All versions of NX-OS for Nexus 3000, 4000, 6000, and 9000 are affected
if (model =~ "^[3469][0-9][0-9][0-9]([Vv])?$") flag++;

# Nexus 5000: 4,x, 5.x, 6.x, are affected, 7.0(0)N1(1) is the first 7.x release
if (model =~ "^5[0-9][0-9][0-9]([Vv])?$")
{
  if (ver =~ "^4\.") flag++;
  if (ver =~ "^5\.") flag++;
  if (ver =~ "^6\.") flag++;
}
# Nexus 7000: 4.x, 5.x, 6.0, 6.1 prior to 6.1(4a), 6.2 prior to 6.2(6) are affected
if (model =~ "^7[0-9][0-9][0-9]([Vv])?$")
{
  if (ver =~ "^4\.") flag++;
  if (ver =~ "^5\.") flag++;
  if (ver =~ "^6\.0") flag++;
  if (ver =~ "^6\.1\([1-3][a-z]?\)") flag ++;
  if (ver =~ "^6\.1\(4\)") flag ++;
  if (ver =~ "^6\.2\([0-5][a-z]?\)") flag ++;
}

# Check for OSPF configured
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCug63304' +
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
