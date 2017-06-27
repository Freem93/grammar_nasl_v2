#TRUSTED 4767d52a8e3ffebbd5511aec44e3bfa0a8d1d00d446ab9e1b51304ba6ed2a9ee187c37e9157b7466737ee891d59b1ca9f23084ae00c616de5a00a60e74cb4b0be3edb0a8e6f4c0cddf303944853416e473cfc29090554a3f6bd40de675287f73a7d4a605682b176594fd8a68dd447d4ce92f7d3f0ad3983825757f9d835ad1ca04f5c46d4684891f4e6b8a32ebc9cdaba468d8862160afc0accc1763497ea7b58b8b375ffdc4d77bba208b1081309583c8a9a128ecef72612a06f51e79ac2e536cc809b6243229a3d20fdc068ee93b26ce1e356e57eb2db235dc2caba060e21c05b7fb12915b1c9e3a5b56ff9481e1610a40affbc9d81e5888086ab5a73776f4cc27d585511a08507f598a91a3c5a0b0eefbff07eecf84a355740c66c8622ad9b1c06d1406a8a1d39295fc2b6cafd197a85d24398cfb599220a67f7c6eeb9ede83cf93af468673939f0026e24991c5ec5fc5cba684167212b196e7d9f971a16ec88b5986bce569de0d1a46e317f17efcc93647ccee9bc91512314662e1c19d8f3c344e522294a3f1cb1e77e61353300305ef5d6c79dedb0ebfa2f5ba1c9597a6a083a1b1bddf172909be62a7acaa70c4a9050a9265cfda797741821214a2035b984fdae0de88a402368c30b51a1b5388d043b1299f8b2be55cbb78ef72ff1ec5febde848ef117997d6771ac56edb10e7e7a83e0d2b77986c49c08dc84a233a46
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82852);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id("CVE-2015-0675", "CVE-2015-0676", "CVE-2015-0677");
  script_bugtraq_id(73966, 73967, 73969);
  script_osvdb_id(120408, 120409, 120410);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq77655");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus95290");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur21069");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150408-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20150408-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch and is therefore affected by the
following vulnerabilities :

  - A flaw exists in the failover ipsec feature due to not
    properly handling failover communication messages. An
    unauthenticated attacker, sending crafted UDP packets
    over the local network to the failover interface, can
    reconfigure the failover units to gain full control.
    (CVE-2015-0675)

  - A flaw exists when handling DNS reply packets, which a
    man-in-the-middle attacker, by triggering outbound DNS
    queries and then sending crafted responses to these, can
    exploit to consume excessive memory, leading to a denial
    of service. (CVE-2015-0676)

  - A flaw exists in the XML Parser configuration when
    handling specially crafted XML messages, which a remote,
    unauthenticated attacker can use to crash the WebVPN
    component, resulting in a denial of service condition.
    (CVE-2015-0677)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150408-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fffe2688");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch or workaround referenced in Cisco Security
Advisory cisco-sa-20150408-asa.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v' # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 1000V or ASAv");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";
report_extras = "";

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

# #################################################
cbi = "CSCur21069";
# #################################################
temp_flag = 0;

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6)"))
{
  temp_flag++;
  fixed_ver = "9.1(6)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.3)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.3)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to check that failover is enabled
# as well as the failover ipsec feature
if (local_check && temp_flag)
{
  temp_flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_failover",
    "show failover"
  );
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"Failover On", string:buf))
    {
      buf = NULL;
      buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config-failover",
        "show running-config failover | include ipsec"
      );
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"failover ipsec", string:buf))
        {
          temp_flag = 1;
        }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
    }
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
cbi = "CSCus95290";
# #################################################
temp_flag = 0;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.28)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.28)";
}
else if (ver =~ "^8\.6[0-9]" && check_asa_release(version:ver, patched:"8.6(1.17)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.17)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.33)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.33)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6)"))
{
  temp_flag++;
  fixed_ver = "9.1(6)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.4)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to check for AnyConnect or clientless ssl vpn
# or anyconnect IKEv2 VPN
if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    # Check for ikev2 enabled
    buf1 = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-crypto-ikev2",
      "show running-config crypto ikev2 | include enable"
    );
    buf2 = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config-webvpn",
      "show running-config webvpn"
    );
    if (check_cisco_result(buf1))
    {
      if (preg(multiline:TRUE, pattern:"crypto ikev2 enable", string:buf1))
      {
        temp_flag = 1;
      }
    }
    else if (check_cisco_result(buf2))
    {
      if (preg(multiline:TRUE, pattern:"webvpn\senable", string:buf2))
      {
        temp_flag = 1;
      }
    }
    else if (cisco_needs_enable(buf1) || cisco_needs_enable(buf2))
    {
      temp_flag = 1;
      override = 1;
    }
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

# #################################################
cbi = "CSCuq77655";
# #################################################
temp_flag = 0;

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.16)"))
{
  temp_flag++;
  fixed_ver = "7.2(5.16)";
}
else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.57)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.57)";
}
else if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.44)"))
{
  temp_flag++;
  fixed_ver = "8.3(2.44)";
}
else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.28)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.28)";
}
else if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.24)"))
{
  temp_flag++;
  fixed_ver = "8.5(1.24)";
}
else if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.17)"))
{
  temp_flag++;
  fixed_ver = "8.6(1.17)";
}
else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.16)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.16)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.33)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.33)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.1)"))
{
  temp_flag++;
  fixed_ver = "9.1(6.1)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(3.4)"))
{
  temp_flag++;
  fixed_ver = "9.2(3.4)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
{
  temp_flag++;
  fixed_ver = "9.3(3)";
}

# Need to that a dns server is configured
# under a DNS server group
if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item(
      "Host/Cisco/Config/show_running-config_dns_server-group",
      "show running-config dns server-group"
    );
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, icase:TRUE, pattern:"name-server\s([0-9]+\.){3}[0-9]+", string:buf))
        temp_flag = 1;
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
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


if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
