#TRUSTED 7ec8473be9619fd6608f055b4260450313081734884faa15b79d3aa5dc21962f4369025f1de963a3070b618d412ac7e8a896a924b573926d0ff4aef4b942eac0d5cdcba2d79ab8cfa34920a3517fbfeb2d6cf0e38552e27b9ea14f1ed20faf2a299673cb817134067e64e341f9210b0575ef39749eba4b8f91194006e9efe0a404f56e6901fa8d0670215e2feb8c775fd8c5e0ad961a13f9c8e9b45ad993ec0cf0acfd9a0624b5a0b2a15ed7fc2819a9df8e42799a513297eb58e4adedd6c107fcd41d3785b94778ea6ace477da03a6ceb1d251a081cf1060918bcd2da09a201657b1dcabc67d3437de98d6ebf71f70e05977905769303d69519819c42fce71ca0bedefeb9dcb44d42856bac9761abf0e4098d72ddd47480ae09ec44fec8bfe1c232997f50991f1c5a8edce54f053eec922b75e877b5026bb0592b2067df4e70076b7216ef13f19ebc31ac7f0c1c9b373c6c69182301acdfd4d3e701483b4fff16450f60037863657e5f6f9b9495ce6bbd3bb7a39738ec26eb60da4ed588b98a9ed4a2e1acfb3e920ba6a36b28444a25455dd1f17a4f7a5c31ed97ed5be07dbcca660b56e30324a87d23c495152ab38b3bec90b3e0314496c5c8a599bf1241f2d4bba318325c51d256e4da76baafd9bead0f480c69af9e33e3a5ae2fe92142e4d27cbe61ea425c444eb5416a72b68cf6183fc76fb9df576b7433fd9ecec4ffbd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93531);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/15");

  script_cve_id("CVE-2015-6327");
  script_bugtraq_id(77262);
  script_osvdb_id(129297);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus94026");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151021-asa-ike");

  script_name(english:"Cisco ASA IKEv1 ISAKMP Packet Handling DoS (cisco-sa-20151021-asa-ike)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper handling of Internet Security
Association and Key Management Protocol (ISAKMP) packets. An
unauthenticated, remote attacker can exploit this, via specially
crafted ISAKMP packets, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?edb2acbc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCus94026");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus94026.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

# Affected
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers
# Cisco ASA 1000V Cloud Firewall
# Cisco Adaptive Security Virtual Appliance (ASAv)

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V'                  &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500 5500-X 6500 7600 1000V or ASAv");

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

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.8)"))
  fixed_ver = "9.1(6.8)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3)"))
  fixed_ver = "9.3(3)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if ASA is configured to terminate IKEv1 VPN connections
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto map | include interface", "show running-config crypto map | include interface");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"crypto map [^\s]+ interface [^\s]+", string:buf))
    {
      # Secondary check to ensure IKEv1 is enabled
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config crypto ikev1", "show running-config crypto ikev1");
      if (check_cisco_result(buf2))
      {
        if ("crypto ikev1 enable outside" >< buf2)
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the system is not configured to terminate IKEv1 VPN connections");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCus94026' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
