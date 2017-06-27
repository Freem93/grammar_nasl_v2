#TRUSTED 84be2c524d5f7e608f194e5da2f8782dcdbd8601859214e9d7264b99557c7f80f435f133c25d329e41d2964b035e8e67c57d6fd93abfafc21b37987f2c8dae8a0343a94be62cad4d298b8c75ec24d7dbbc1f328dd4923afe7695ede17ac70adfc66d334078697e1e708b78e2b34a8df67184ac8f7b337945a3674401b2231ac000238c070eb890308af03a3afb511fdbce2eb92d11ff6cdd74c3cc8a4079c9b4f5d3fa88c92c08dc909d0a5c12610c7df6e0bd58a336e40b0d65ec9bd69c00f62c68257864bfa67fff1fd2d8afec4e799b921519cab6d2c25e375a57eb45514e3d00bef39c26cf88d8223a3178fffb1a12402c3f0052218951946ddeadadf781df19b578afb2d1130d7819bf0b6d6cce55c4e23d1d3ec80f7aae0eda53703fb95a14418419182496a604fb1f309e20402a0341721909df0fff1da44dd444417492d1345197a3e4e79f4fe41dd21f7c094d25223eedb6cd8c9fc560d3abc3f95f52e6337ad89e2f8f22a7d08490fc8e244a4bf2b453efe42c33a76596130f370ec549487fc5d3e53a51702bdaccdefbf3d4211b474775b01889fb4df02c0c7883a66d3d89d4f9cdf493eac430faf8e4150167d6dfbb9069bb5a911b5adeec805e40b2b6e3c64a4106a68103e4a5551f9c0f8fed96f5ef6eb21d5d0347425c5671ffa88b4e662ce519fbfad79759ccc81630b58c8c5c9266232b89210cd241e7af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74036);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/11/01");

  script_cve_id("CVE-2014-2182");
  script_bugtraq_id(67100);
  script_osvdb_id(106418);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun45520");

  script_name(english:"Cisco ASA DHCPv6 Relay DoS (CSCun45520)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the remote Cisco ASA device is
affected by a denial of service vulnerability due to improper
validation of packets when the IPv6 for DHCP (DHCPv6) relay feature is
enabled. An unauthenticated attacker on an adjacent network could
cause a denial of service by sending a specially crafted DHCP packet.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-2182
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99a2eb32");
  # http://tools.cisco.com/security/center/viewAlert.x?alertId=33980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ed1ed56");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco Bug Id CSCun45520.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (model !~ '^55[0-9][0-9](|-)X($|[^0-9])')
  audit(AUDIT_HOST_NOT, 'ASA 5500-X');

fixed_ver = NULL;

if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.8)"))
  fixed_ver = "9.0(4)8";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.2)"))
  fixed_ver = "9.1(5)2";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCPv6 relay feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ipv6 dhcprelay server", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the DHCPv6 relay feature is not enabled.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
