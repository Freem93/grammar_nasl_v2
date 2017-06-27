#TRUSTED 55c0fcf1632f6555bde4b178233e5010e32032a274b5d2186da84a8fc96d38901f790119f0c10062c4f42d335d1370c8a3c7dbd7f27bc4f589223b22b008e4225c1d7f430e0af0800f02ef16e0011d22f358e92a01f6cfd45233548098fb11f7f4fdbe7c07b5a4a1d8f2af622faff7466b39855a4c6893035bac516440b2d51a8627acfc7318818b6359d319fe1bd0f59711bc741eefb98193b4903303dca44be3558b2c97bfe5147cb9be72a39c2b7c5301457da089e30a20439a555d90482e2d9e80a5ec05042ef7584d5e3e09bba88e8090f202ff22788fa3373dc6197368e35436797b768591c262924b89d10e91e2dbff9e06696d4b4e28fa7cfb67568b896138996b904b6d510d18e53e9cc3a3a359276fc6129461a127b49cdbd5ec05db0c3f6b05eb97ec6bd6a1fb4c32442fe06786bc8b2f282894aeb2e50d1d7b306a02cc5b4986ce2d875dff68009e5087be61203348f44e9e14474d47eb5661f629f037e461fe166d55d80df426f9978d0f7f0962288d2a209218c6f9f628c9d396b8571518f7d864462b0b97a7d858172ce3e8925f330e6b5866150d7636667b0c5369d070e1baf7d82db5661fc3d5471de7186923d24c553ef3db59c804ff43efd84db87e17993aee571580ba7bfd3e6bb85e87784f04232ba8e78f4d65595eab8c5703fb56bad2faa27c7cacb2329d2c46b96c3ba416818254539af2f21973
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88713);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id("CVE-2016-1287");
  script_bugtraq_id(83161);
  script_osvdb_id(134373);
  script_xref(name:"CERT", value:"327976");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux29978");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux42019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160210-asa-ike");

  script_name(english:"Cisco ASA Software IKEv1 and IKEv2 UDP Packet Handling RCE (cisco-sa-20160210-asa-ike)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a remote
code execution vulnerability due to an overflow condition in the
Internet Key Exchange (IKE) implementation. An unauthenticated, remote
attacker can exploit this, via specially crafted UDP packets, to cause
a denial of service or the execution of arbitrary code. Note that only
systems configured in routed firewall mode and single / multiple
context mode are affected.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160210-asa-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafc4e71");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20160210-asa-ike.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
  model !~ '^1000V'                  &&
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5000-X 6500 7600 1000V 9300 3000 or ASAv");

flag = 0;
override = 0;
local_check = 0;
fixed_ver = "";
report = "";

cbi = "CSCux29978 and CSCux42019";

# For each vulnerability, check for affected OS versions,
# set "fixed" os version, and perform any additional checks

# Determine if additional local checks can be performed
if (get_kb_item("Host/local_checks_enabled")) local_check = 1;

if (ver =~ "^7\.2[^0-9]" || ver =~ "^8\.3[^0-9]" || ver =~ "^8\.6[^0-9]")
{
  temp_flag++;
  fixed_ver = "9.1(6.11)";
}
else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.59)"))
{
  temp_flag++;
  fixed_ver = "8.2(5.59)";
}
else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.30)"))
{
  temp_flag++;
  fixed_ver = "8.4(7.30)";
}
else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.18)"))
{
  temp_flag++;
  fixed_ver = "8.7(1.18)";
}
else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.38)"))
{
  temp_flag++;
  fixed_ver = "9.0(4.38)";
}
else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.11)"))
{
  temp_flag++;
  fixed_ver = "9.1(6.11)";
}
else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4.5)"))
{
  temp_flag++;
  fixed_ver = "9.2(4.5)";
}
else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.7)"))
{
  temp_flag++;
  fixed_ver = "9.3(3.7)";
}
else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(2.4)"))
{
  temp_flag++;
  fixed_ver = "9.4(2.4)";
}
else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(2.2)"))
{
  temp_flag++;
  fixed_ver = "9.5(2.2)";
}

# Need to check that failover is enabled
# as well as the failover ipsec feature
if (local_check && temp_flag)
{
  temp_flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_crypto_map",
    "show running-config crypto map | include interface"
  );
  # Output for vuln config will be like:
  # crypto map <some map name> interface <some interface name>
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"crypto map [^\s]+ interface [^\s]+", string:buf))
        temp_flag = 1;
  }
  else if (cisco_needs_enable(buf)) {temp_flag = 1; override = 1;}
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug IDs     : ' + cbi +
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
