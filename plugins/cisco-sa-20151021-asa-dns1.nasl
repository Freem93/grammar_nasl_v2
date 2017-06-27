#TRUSTED 775a5199ad4fe6ab2145623b6359014f2a9d906b8e554430057d5f04767ec8bec62101b5b11c047ebd10d768a2ecd55300c50eba8c2afe81e01d9aad57b7cd4fa9c66f58b5f19aeeb6188cdb9aceacfb243a6c9c2d7e11114b53a5e25e28596ef1deba43413933cdaae9ef1bc7e265dbfcdf36d447d9a8b3fe7bc1e15504cfceee029bf6dfd8a7f9a3bce6b680a6da11723f3288a48778a27b7af82a640daf2e777542a9ac606b0fc5f8c94150bd65c8662bb1bd3601cf408525a7fd3f2f983a67f5f186c8af7e2e079930e47552cf52b7b606856d7803a60d2a0cf926978c0e9dc68348e59db7d789c60273f9e48a67cd56b0c78beb0244109a09493b7900d5c038cd193ed81667c53da98cf122e418ad6c141828950f9735c0f5fa9343b5e2a6311d4ba5e26ebf0d4fb1a5c9a99bbb4a8e54c3df8164eb79409347c8dad51fe79fa87c0cb15928b83391f6bc91a48b1bec555abe9e44cf39991ce8de0863c51c2c784f55cb91b25fe7ef70b2fde741f1f0fb9fe517ec595e71cf8b99d507658fc20d9fd7a839ca7c893773539a60f4bd634b461caa9f335508628ea24d7c191546b5bb050ef065a44f673a9e42d7f00fc127888ec4c84dcb6cf81a8ec9498722d1065e15c08a216d846ca55f4ca67579db765de83d5c1a295c40059e144c2e94e976a88a8d6b18b90f835fea8b5c9512c7749ffe39690cd2be263679a2baed
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93529);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/09/15");

  script_cve_id("CVE-2015-6325");
  script_bugtraq_id(77260);
  script_osvdb_id(129295);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut03495");
  script_xref(name:"CISCO-SA", value: "cisco-sa-20151021-asa-dns1");

  script_name(english:"Cisco ASA DNS Packet Handling DoS (cisco-sa-20151021-asa-dns1)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the remote Cisco Adaptive
Security Appliance (ASA) device is affected by a denial of service
vulnerability due to improper processing of DNS packets. An
unauthenticated, remote attacker can exploit this, via a spoofed reply
packet with a crafted DNS response, to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151021-asa-dns1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1ee734e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut03495");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCut03495.
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
# Cisco Adaptive Security Virtual Appliance (ASAv)
# Cisco ASA 1000V Cloud Firewall
# Cisco ASA 5500 Series Adaptive Security Appliances
# Cisco ASA 5500-X Series Next-Generation Firewalls
# Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches
# and Cisco 7600 Series Routers

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model !~ '^1000V' &&
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

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(6.4)"))
  fixed_ver = "9.1(6.4)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(4)"))
  fixed_ver = "9.2(4)";

else if (ver =~ "^9\.3[^0-9]" && check_asa_release(version:ver, patched:"9.3(3.1)"))
  fixed_ver = "9.3(3.1)";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.1)"))
  fixed_ver = "9.4(1.1)";

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
    '\n  Cisco bug ID      : CSCut03495' +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
