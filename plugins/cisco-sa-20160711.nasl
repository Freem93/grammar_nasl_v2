#TRUSTED 229ac0bbaddd3f00e5378b76b8f384f8ad48b62424c41a7aa339fbb6d41625bb14b14910b43e1b2e8e211be3a1bdb78ed50455eeee7e8efa33bee61108963e0a16870a4b17e636c348d6fc4d19e605a8a23c4d79f862fc28af4983cbd8856cb06b39cb30f202e950438a306608e97650f8d51be1f4d1d7b0ec104d52444ae1430ff21955429d57cc1068e9e58bc49ca49c6a231ed101874b3b14f69f6b1d1d80f8af3645a681f229399346ded456dca8f8f8958cf622390fcf7720d92459557ea82ccde78770b879a332f302485472d66c9a2298e9698730a7a8e4effaee9927b1606fc0d5317f798891b3fc514e4463aaed06eaa2aafe2643b89c76f7dc13a12cef18b82ceeb6a4860a89469ef244732c69f96ff536d1dd9ba91ba09f56fdde55b86e2aff5c7f0e2f228331c2d82b059f8442dfda4c607501fc61636f7bcbe9a86974ed89167b953e32bc7a789c833a7a81e073ac5250113e960d31773075cbd13a5b081b81e5917fdd1355daa22bd015d0a27b043aa76cf0576ef0eb2568cd8e74161d718d5d31cf6ba1c9eabd0ad5ec8c4cb2604376be39e1412f4c254239a80aba5ed5ad411b619cfd7736ab97aa1a27d0cba83e2187ddb263fe8e2820bf772819d5b87be9bd7e07013004c50d30786a27459d8956b330a06a805781f0249e95f8bb9ea1d7b455ccd0ea070a606bb70430ce5dd5e2222f54c7fb279d26d0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92630);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/27");

  script_cve_id("CVE-2016-1445");
  script_bugtraq_id(91693);
  script_osvdb_id(141287);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy25163");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160711-asa");

  script_name(english:"Cisco Adaptive Security Appliance ICMP Echo Request ACL Bypass (cisco-sa-20160711-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software running on the remote device is
version 8.2.x or 9.4.x prior to 9.4(3.3), 9.5.x prior to 9.5(2.10),
or 9.6.x prior to 9.6(1.5). It is, therefore, affected by an ACL
bypass vulnerability due to a flaw in the implementation of ACL-based
filters for ICMP echo requests and the range of ICMP echo request
subtypes. An unauthenticated, remote attacker can exploit this, by
sending ICMP echo request traffic, to bypass ACL configurations on the
affected device, allowing ICMP traffic to pass through that otherwise
would be denied.

Note that ICMP must be enabled for the device to be affected by this
vulnerability.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160711-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4fa89b9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy25163.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/29");

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

asa   = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');
fixed_ver = NULL;

if (ver =~ "^8\.2[^0-9]")
  fixed_ver = "Refer to vendor.";

else if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(3.3)"))
  fixed_ver = "9.4(3.3)";

else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(2.10)"))
  fixed_ver = "9.5(2.10)";

else if (ver =~ "^9\.6[^0-9]" && check_asa_release(version:ver, patched:"9.6(1.5)"))
  fixed_ver = "9.6(1.5)";
if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_accesslist", "show running-config | include access-list");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"permit icmp", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

security_report_cisco(
  port     : 0,
  severity : SECURITY_WARNING,
  override : override,
  version  : ver,
  fix      : fixed_ver,
  bug_id   : "CSCuy25163",
  cmds     : make_list("show running-config | include access-list")
);
