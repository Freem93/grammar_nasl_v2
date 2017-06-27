#TRUSTED 18df61be7eeb20aaabaa4f1324675a17cf7856814a26e6deba0b1021f36ad0b459a2bbd4e2d8bc74d59db317969756d437e34633f4ddb443331b99bbf736f1fb2358b67621caa83e4862e57f9bf9cc32b5801b8eee9b50ef3189c8c44cf109ca624149d8ebe4046c3af344339fd02adfce0a32459fcf1f0972650914813d465b1ead7307799916119498316ed8a6b7fdd4922080379502caa3ac41ff919d18888c0a8467c3f9e67df7384959eb318e193c7d3deea264fd0367f81e39616bb8d181d248ac79dba693f4ac3a8b31a99b8c224e276993d840efa7dd445de9f82466216f60516ea650bc71972329fc37e82b6f67a0d85119d2e1e292403331838c1f1f22767fc7d0868ef6b03983baa84ed9eb9d353d89519a3061239fdbebf1847bc991c19cd4c8a7cbb1fd6e943f54a1f705b7fc6f5bc3217dd619e0541179c8871b809a0cd8abba1cd8ad1180eed54fb01a71d2b97cfdfa9b1f77cebf87cf3bbeb24c4c5c52e9bd0a0df6878e370f787113bc1079a751a303f4f67f30d6bccb827f53eeb09e2cf03085211738f0ae8001dfec36719034037e69324958d8b559ae5cc2cbd6617298ee763345c0146476243710c5341c180d7d5c444654ba1b2058441b3572af0ef6886aa2bfc840349cfd343cfcf68b52fe2910da105fb65c4c364397ce883fc51a7bbe353dce6d772e604e61d8df0a37a49727ea0957a31a698e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93528);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/15");

  script_cve_id("CVE-2015-6324");
  script_bugtraq_id(77257);
  script_osvdb_id(129294);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus56252");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus57142");
  script_xref(name:"CISCO-SA", value: "cisco-sa-20151021-asa-dhcp1");

  script_name(english:"Cisco ASA DHCPv6 Relay DoS (cisco-sa-20151021-asa-dhcp1)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability in the DHCPv6 relay feature due to improper validation
of DHCPv6 packets. An unauthenticated, remote attacker can exploit 
this, via specially crafted DHCPv6 packets, to cause the device to
reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dhcp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cad6d0f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus56252");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus57142");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug IDs CSCus56252 and
CSCus57142. Alternatively, disable the DHCPv6 relay feature.");
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
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches and
# Cisco 7600 Series Routers
# Cisco ASA 1000V Cloud Firewall
# Cisco Adaptive Security Virtual Appliance (ASAv)

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V or ASAv");

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.37)"))
  fixed_ver = "9.0(4.37)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.6)"))
  fixed_ver = "9.1(6.6)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.6)"))
  fixed_ver = "9.3(3.6)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(2)"))
  fixed_ver = "9.4(2)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6-dhcprelay", "show running-config ipv6 dhcprelay");
  if (check_cisco_result(buf))
  {
    if ("ipv6 dhcprelay enable outside" >< buf) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because DHCP6 relaying is not enabled");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCus56252 and CSCus57142' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
