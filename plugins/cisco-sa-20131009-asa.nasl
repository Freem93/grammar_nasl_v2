#TRUSTED 269fbf408bf0f0ca89b80f5ebac142a87bec1bd4c30a374e28308681f352701681213e629f1db3e721015415bdc340472c2a225ad804d1760e01ecae36193aee5d85653c3cae84b3e295a008d111378fbd34df0864227b4ccb2979d76a51367eeb86937b70d221574ef75ef953ea82cf7573a2d353c13d83a56cc206656dc153f349fc0ae6599407fae1b9ee1ceca25107634c5b49e72ac0cf94d7db6c9b9d8a232c0e57187ebaf5250f4220a877a4395b0b143c87d0efa2f57fd72608746424e73d7fde3ae727d01f7b7955ee5bc37909de1e195a1af56a3b65012ca7f92f45a5451c0ff25f565b2d2bbe0ae5d171cfeb38aa2da4f596341975bf3b21b219d1b9fdcc115d8bfe433476cd35dbb8bc2de8014ea2431598cd37ea6a8edfbb82523650fe6efb19197c7748c1f0e90491fa7c9a0e0d207a8c5fd5818a5f4d0e0b80a9e96c9bdf04811f7ff2d9ae9bf4df5f895262de4acc016a8e07a80d4f7cc02f96eff369b5b8fae2f4b456857bfd40a04c919637913e662cbdd3bd26a85370613c05f44f026cf471eab934bd3c2b64c520af69f384afb8eb1472771054c8861157925814f2ff2d8da275bcd2bd2a760f1b00d19ac65e29659264dd2d3f478fc7d7aacc9714cad1199c2be2b72308a4406f2c9835457da02a3c15cf91bba7e4b8345c9da4b2883e8bb8f9fa38193aa68d6c5f52fa6bc1186af3045b49b466ae22
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70474);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/05/14");

  script_cve_id(
    "CVE-2013-3415",
    "CVE-2013-5507",
    "CVE-2013-5508",
    "CVE-2013-5509",
    "CVE-2013-5510",
    "CVE-2013-5511",
    "CVE-2013-5512",
    "CVE-2013-5513",
    "CVE-2013-5515",
    "CVE-2013-5542"
  );
  script_bugtraq_id(
    62910,
    62911,
    62912,
    62913,
    62914,
    62915,
    62916,
    62917,
    62919,
    63202
  );
  script_osvdb_id(
    98255,
    98257,
    98258,
    98259,
    98260,
    98261,
    98262,
    98263,
    98264,
    98685
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCtt36737");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua22709");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub98434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud37992");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue18975");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf52468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug03975");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug83401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh44815");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui77398");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cisco-sa-20131009-asa");

  script_name(english:"Cisco ASA Software Multiple Vulnerabilities (cisco-sa-20131009-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco ASA device is affected by one or more of the 
following vulnerabilities :

  - A denial of service vulnerability exists due to improper
    clearing of unused memory blocks after an AnyConnect SSL
    VPN client disconnects. (CVE-2013-3415)

  - A denial of service vulnerability exists resulting from
    an error in the code that decrypts packets transiting an
    active VPN tunnel. (CVE-2013-5507)

  - A denial of service vulnerability exists due to improper
    handling of segmented Transparent Network Substrate
    (TNS) packets. (CVE-2013-5508)

  - An authentication bypass vulnerability exists resulting
    due to an error in handling a client crafted certificate
    during the authentication phase. (CVE-2013-5509)

  - An authentication bypass vulnerability exists due to
    improper parsing of the LDAP response packet received
    from a remote AAA LDAP server. (CVE-2013-5510)

  - An authentication bypass vulnerability exists due to an
    error in the implementation of the
    authentication-certificate option. (CVE-2013-5511)

  - A denial of service vulnerability exists due to improper
    handling of a race condition during inspection of HTTP
    packets by the HTTP DPI engine. (CVE-2013-5512)

  - A denial of service vulnerability exists due to the
    improper processing of unsupported DNS over TCP packets
    by the DNS inspection engine. (CVE-2013-5513)

  - A denial of service vulnerability exists resulting from
    the improper handling of crafted HTTPS requests for
    systems configured for Clientless SSL VPN.
    (CVE-2013-5515)

  - A denial of service condition can be caused by improper
    handling of crafted ICMP packets. (CVE-2013-5542)

Note that the verification checks for the presence of CVE-2013-5513
and CVE-2013-5515 are best effort approaches and may result in
potential false positives.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131009-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03a428f7");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31107
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e290b3ad");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?255c2bd8");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31104
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c310e2c");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31106
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51062d03");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31102
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfcbecc4");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31105
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14a2e479");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9ce8c3b");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1afee31");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=31100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8ef1aa0");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131009-asa.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_6500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_7600");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_1000V");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

# Verify that we are targeting an affected hardware model
#   Cisco ASA 5500 Series Adaptive Security Appliances
#   Cisco ASA 5500-X Next Generation Firewall
#   Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
#   Cisco 7600 Series Routers
#   Cisco ASA 1000V Cloud Firewall
if (
  model !~ '^55[0-9][0-9]' &&
  model !~ '^65[0-9][0-9]' &&
  model !~ '^76[0-9][0-9]' &&
  model !~ '^1000V'
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 or 1000V");

flag = 0;
report_extras = "";
fixed_ver = "";
local_check = 0;
override = 0;

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (
  get_kb_item("Host/local_checks_enabled") 
) local_check = 1;

# #################################################
# CSCue18975
# #################################################
cbi = "CSCue18975";
temp_flag = 0;

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.7)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)7";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_crypto_map", "show running-config crypto map");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"crypto map .*interface", string:buf)) { temp_flag = 1; }
    } else if (cisco_needs_enable(buf)) { temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}
# #################################################
# CSCuf52468
# #################################################
cbi = "CSCuf52468";
temp_flag = 0;

# Verify additional Hardware restrictions
if (
  model != '5505' &&
  model != '5510' &&
  model != '5520' &&
  model != '5540' &&
  model != '5550'
)
{
  if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.6)"))
  {
    temp_flag++;
    fixed_ver = "9.0(2)6";
  }

  if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2)"))
  {
    temp_flag++;
    fixed_ver = "9.1(2)";
  }

  if (local_check)
  {
    if (temp_flag)
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"enable", string:buf))
        {
          buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_tunnel-group_AnyConnect-TG", "show running-config tunnel-group AnyConnect-TG");
          if (check_cisco_result(buf))
          {
            if (preg(multiline:TRUE, pattern:"authentication .*certificate", string:buf)) { temp_flag = 1; }
          }
          else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
        }
      } 
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      if (!temp_flag)
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_http", "show running-config http");
        if (check_cisco_result(buf))
        {
          if (
            preg(multiline:TRUE, pattern:"http server enable", string:buf) &&
            preg(multiline:TRUE, pattern:"(http authentication-certificate|ssl certificate-authentication interface)", string:buf)
          ) { temp_flag = 1; }
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
    }
  }

  if (temp_flag)
  {
    report +=
      '\n  Cisco bug ID        : ' + cbi +
      '\n    Installed release : ' + ver +
      '\n    Fixed release     : ' + fixed_ver + '\n';
    flag++;
  }
}

# #################################################
# CSCub98434
# #################################################
cbi = "CSCub98434";
temp_flag = 0;

if (ver =~ "^7\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.12)"))
{
  temp_flag++;
  fixed_ver = "7.2(5)12";
}

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.44)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)44";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.6)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)6";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.10)"))
{
  temp_flag++;
  fixed_ver = "9.0(2)10";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_service-policy_include_sqlnet", "show service-policy | include sqlnet");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ii]nspect\s*:\s*sqlnet", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCug03975
# #################################################
cbi = "CSCug03975";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7)"))
{
  temp_flag++;
  fixed_ver = "8.4(7)";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.7)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)7";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.3)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)3";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.8)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)8";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map", "show running-config policy-map");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"inspect dns preset_dns_map", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCug83401
# #################################################
cbi = "CSCug83401";
temp_flag = 0;

if (ver =~ "^7\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "7.2.x or later";
}

if (ver =~ "^7\.2[^0-9]" && check_asa_release(version:ver, patched:"7.2(5.12)"))
{
  temp_flag++;
  fixed_ver = "7.2(5)12";
}

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)6";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)1";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.5)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)5";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_tunnel-group_AnyConnect-TG", "show running-config tunnel-group AnyConnect-TG");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"override-account-disable", string:buf) && preg(multiline:TRUE, pattern:"authentication-server-group", string:buf))
      {
        temp_group  = eregmatch(string:buf, pattern:"authentication-server-group\s+([^\r\n]+)");
        buf = cisco_command_kb_item("Host/Cisco/Config/show_aaa-server_protocol_ldap", "show aaa-server protocol ldap");
        if (check_cisco_result(buf))
        {
          temp_pat = "Server Group:\s*" +  temp_group;
          if (preg(multiline:TRUE, pattern:"Server Protocol: ldap", string:buf) && preg(multiline:TRUE, pattern:temp_pat, string:buf)) { temp_flag = 1; }
        }
        else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
      }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCtt36737
# #################################################
cbi = "CSCtt36737";
temp_flag = 0;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(3)"))
{
  temp_flag++;
  fixed_ver = "8.4(3)";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.3)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)3";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"svc enble", string:buf) || preg(multiline:TRUE, pattern:"anyconnect enable", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCud37992
# #################################################
cbi = "CSCud37992";
temp_flag = 0;

# Verify additional Hardware restrictions
if (
  model != '5505' &&
  model != '5510' &&
  model != '5520' &&
  model != '5540' &&
  model != '5550'
)
{
  if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
  {
    temp_flag++;
    fixed_ver = "8.2(5)46";
  }

  if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
  {
    temp_flag++;
    fixed_ver = "8.3(2)39";
  }

  if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(5.5)"))
  {
    temp_flag++;
    fixed_ver = "8.4(5)5";
  }

  if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
  {
    temp_flag++;
    fixed_ver = "8.5(1)18";
  }

  if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
  {
    temp_flag++;
    fixed_ver = "8.6(1)12";
  }

  if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.4)"))
  {
    temp_flag++;
    fixed_ver = "8.7(1)4";
  }

  if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(1.4)"))
  {
    temp_flag++;
    fixed_ver = "9.0(1)4";
  }

  if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.2)"))
  {
    temp_flag++;
    fixed_ver = "9.1(1)2";
  }

  if (local_check)
  {
    if (temp_flag)
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_policy-map_type_inspect_http", "show running-config policy-map type inspect http");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"spoof-server", string:buf)) { temp_flag = 1; }
        if (preg(multiline:TRUE, pattern:"filter java", string:buf)) { temp_flag = 1; }
        if (preg(multiline:TRUE, pattern:"filter activex", string:buf)) { temp_flag = 1; }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
    }
  }

  if (temp_flag)
  {
    report +=
      '\n  Cisco bug ID        : ' + cbi +
      '\n    Installed release : ' + ver +
      '\n    Fixed release     : ' + fixed_ver + '\n';
    flag++;
  }
}

# #################################################
# CSCuh44815
# #################################################
cbi = "CSCuh44815";
temp_flag = 0;

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.46)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)46";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(6.6)"))
{
  temp_flag++;
  fixed_ver = "8.4(6)6";
}

if (ver =~ "^8\.5[^0-9]" && check_asa_release(version:ver, patched:"8.5(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.5(1)18";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.7)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)7";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.1)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)1";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.6)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)6";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_http", "show running-config http");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"http authentication-certificate", string:buf)) { temp_flag = 1; }
      if (preg(multiline:TRUE, pattern:"ssl certificate-authentication interface", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCua22709
# #################################################
cbi = "CSCua22709";
temp_flag = 0;

if (ver =~ "^8\.0[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.1[^0-9]")
{
  temp_flag++;
  fixed_ver = "8.2.x or later";
}

if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.44)"))
{
  temp_flag++;
  fixed_ver = "8.2(5)44";
}

if (ver =~ "^8\.3[^0-9]" && check_asa_release(version:ver, patched:"8.3(2.39)"))
{
  temp_flag++;
  fixed_ver = "8.3(2)39";
}

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(5.7)"))
{
  temp_flag++;
  fixed_ver = "8.4(5)7";
}

if (ver =~ "^8\.6[^0-9]" && check_asa_release(version:ver, patched:"8.6(1.12)"))
{
  temp_flag++;
  fixed_ver = "8.6(1)12";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(2.6)"))
{
  temp_flag++;
  fixed_ver = "9.0(2)6";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(1.7)"))
{
  temp_flag++;
  fixed_ver = "9.1(1)7";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"enable", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCui77398
# #################################################
cbi = "CSCui77398";
temp_flag = 0;

# advisory states that the issue will be fixed at least by 8.4(7.2) however,
# at the time this plugin was written, the latest known version was 8.4(7)
if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7"))
{
  temp_flag++;
  fixed_ver = "8.4(7)2";
}

# advisory states that the issue will be fixed at least by 8.7(1.8) however,
# at the time this plugin was written, the latest known version was 8.7(1.1)
if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.1)"))
{
  temp_flag++;
  fixed_ver = "8.7(1)8";
}

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(3.6)"))
{
  temp_flag++;
  fixed_ver = "9.0(3)6";
}

if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(2.8)"))
{
  temp_flag++;
  fixed_ver = "9.1(2)8";
}

if (local_check)
{
  if (temp_flag)
  {
    temp_flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_icmp", "show running-config icmp");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"icmp permit any", string:buf)) { temp_flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }

    if (!temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_ipv6", "show running-config ipv6", 0);
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"ipv6 icmp permit any", string:buf)) { temp_flag = 1; }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
    }

    if (!temp_flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"inspect icmp", string:buf)) { temp_flag = 1; }
      }
      else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1; }
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

if (flag)
{
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
