#TRUSTED 4255d079be67a80a63fccd1f33e3c15109dc0454ce109bff5d4d08e0193edb8b8194617b10c8a045e443618cf1c08adf6b125dcafe30069e15fe11199fd7e89e767737e8dc184f2d6fc9884d9eb86ef45a9462a55789cc02214710523a6b2bbf5a6f88c6a56eb2e0969c4a0e56bdf5c319e7adc81a723083660afe2077d575bc83ea1035b6552b0676aa70bafe7a696b98d9000e278c5853189d6d2b1eedca596cba6dc93509e04d6919882eaeea5ca6eed716a6c82dbd065bdcd3cd816dd14eb0e7d00f1dc37dc80c5e78734f06a7bda7a0ff63d402a1eceab4ef2135b1226b015c29e8f768044ea7146ce13b989ba2ea511e8c52c91c05053ff0c6db3cedd5d89f82f64f7b2338e12a42318f6dff9bdc92831ee88f7e8af4daf16d0d911881fe052bcca5976b9545de62b9affd23eb02b3de2ddae1ebfce54199242f7391e9f058d333f5b1afa2981158348363ad6ae4f7cd8e20b2f2bec5555ef2dc1f27a0bbea4ff09a1cc52a8c9ae441d3ca58215cb4766ca533e523202b22b4049e87629d8bd68567edf6070ded099a50fc5ffa03670ccd9c3c563efb7571471c5a4594147d1935931e1426da046d77fbd311e547cf41ca87d66281f43ac506660fd2b4472e5ef40109e4694ce1abbf9d79f331de46b41030a253a81800bfff7042c73b3d48dc1b1e1a158bc9bd8947566fe56f28ad416f0cee2bc1c9a805a7d2271ea9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93530);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/15");

  script_cve_id("CVE-2015-6326");
  script_bugtraq_id(77261);
  script_osvdb_id(129296);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu07799");
  script_xref(name:"CISCO-SA", value: "cisco-sa-20151021-asa-dns2");

  script_name(english:"Cisco ASA DNS Packet Handling DoS (cisco-sa-20151021-asa-dns2)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper processing of DNS packets. An
unauthenticated, remote attacker can exploit this, via a spoofed reply
packet with a crafted DNS response, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dns2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1387798a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu07799");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuu07799.
Alternatively, remove DNS name-server values configured for any DNS
server groups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected :
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco FirePOWER 9300 ASA Security Module

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^93[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V 9300 or ASAv");

fixed_ver = NULL;

if (ver =~ "^7\.2[^0-9]")
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.2[^0-9]" && check_asa_release(version:ver, patched:"8.2(5.58)"))
  fixed_ver = "8.2(5.58)";

else if (ver =~ "^8\.3[^0-9]")
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.29)"))
  fixed_ver = "8.4(7.29)";

else if (ver =~ "^8\.5[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.6[^0-9]")
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^8\.7[^0-9]" && check_asa_release(version:ver, patched:"8.7(1.17)"))
  fixed_ver = "8.7(1.17)";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.6)"))
  fixed_ver = "9.1(6.6)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.6)"))
  fixed_ver = "9.3(3.6)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.5)"))
  fixed_ver = "9.4(1.5)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if at least one DNS server IP address is configured
# under a DNS server group
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config dns server-group", "show running-config dns server-group");

  if (check_cisco_result(buf))
  {
    if (
      ("DNS server-group" >< buf) &&
      (preg(multiline:TRUE, pattern:"name-server [0-9\.]+", string:buf))
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because a DNS server IP address is not configured under a DNS server group");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuu07799' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
