#TRUSTED 111ad998337505dda91598ea306009510abafc27b85ecc411bffc1ccf760254105481e15ae86840b14b7b9b30c95d09256cf733cc37e984f0f4075fcce5f744393d44fd21dfcc8608d765d3da3b40f7d11d232362c6f4d661abbc3bcd772e26eb331b80ee8e0b3dd532d47b0a5f038f3905821994db5c63ef8e3732e1729e08966c9d0f81e9953ea213e67474b793eed95dd92d3dfe73b3e7587847c2620a443192f715a44333a4d9729b0bac7b0e4c434d41a5ca0b8840f11f35353b54ebe7acb11984791827558e2eb594922414418ef2a7ec46e4a8d2b0a8201dfcceaf61925c1ff5347a503ddb895fdf0a2b457af1ae2527ba2d3d0331cdab352a464acf6fb864690b80a563ff9fad97c8aa2a8457ade39a07415452a39cb1eaf533d1ae4ca76043b194d4ca7d34dbd3b9ee1906b21ba07878596b0214e18e76a7e5366469202dd97ef9d4e24bd8b4b14d870999e78240196e966f1810c2f9762e85d6a1e505006f9e3f343d89b08c9624aef3e17d5a1edff5b92f50198458077b9c3a8a5051bdd49b450f691483c73b1fe9f13c7e4a6502c50f5549bb809753852434b428ef6df38333f34470cff00eb2f284ad9506a8dba3a0b345df34d82f49f510e313e25eecf00fb13288fb5fa3160d4a82dfcbc4d5ce6893568d74c76227f11434b4164be233d4454373e78364d01e55043172071014dd73dab6b913be52d0be4d8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90714);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/26");

  script_cve_id("CVE-2016-1367");
  script_osvdb_id(135336);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-asa-dhcpv6");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus23248");

  script_name(english:"Cisco Adaptive Security Appliance Software DHCPv6 Packet Handling DoS (cisco-sa-20160420-asa-dhcpv6)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) device is affected
by a denial of service vulnerability in the DHCPv6 relay feature due
to improper validation of DHCPv6 packets. An unauthenticated, remote
attacker can exploit this, via specially crafted DHCPv6 packets, to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-asa-dhcpv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ac65dfd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus23248. Alternatively, disable the DHCPv6 relay feature.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/20");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
#  Cisco ASA 5500-X Series Next-Generation Firewalls
#  Cisco ASA Services Module for Cisco Catalyst 6500 Series Switches and Cisco 7600 Series Routers
#  Cisco Adaptive Security Virtual Appliance (ASAv)
if (
  model !~ '^55[0-9][0-9]-?X' &&
  model !~ '^65[0-9][0-9]($|[^0-9])' &&
  model !~ '^76[0-9][0-9]($|[^0-9])' &&
  model != 'v'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "ASA 5500-X/6500/7600 or ASAv");

fixed_ver = NULL;

if (ver =~ "^9\.4[^0-9]" && check_asa_release(version:ver, patched:"9.4(1.1)"))
  fixed_ver = "9.4(1.1)";

else
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

override = FALSE;

# Check if DHCP6 relay is in play
if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-ipv6", "show running-config ipv6");
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
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
