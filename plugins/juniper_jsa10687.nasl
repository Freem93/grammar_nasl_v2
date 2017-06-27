#TRUSTED 0a07481e670c24919ae6e4ce6d68dedee14b8a0ac2f346baa18cde17a747a9d3c9848b8d9bb8ab6a620d0bcb6c9e6fddf1daf8d5580f9011d567b6df67138146cd35fe48d9a60b01f4e21176320691719679ef39efa42d446c8db6cc9e76b195ae786f33f1bea2ce4ef752e32bbf0aa628b5aa2adec6dbeee5dbf7d5d835e64a8865ba2551d64b9e4fe491f77e0cc725ce00c73032635c8e00734996a46e37f49e7f772cb79e764f85f016e184910f5dd71765640cfa8ec5116b8f252dc75878ea6621378b38e54f267fe36481cea5163bd1349ca71063939a7012c128d8547ff7c959fdd3540073125f831786bb433f88b56fb68951229493191f5a2e8a4a4b082679e023afeb4f6de1733b926c1c58e7f00f2ae584a3d58843dae872401ae8b27ed263f6ef7ddad9f9050c2a54b23bdca1298efc05c15f3ffec511556c339d22d39842510bf71a28020ee1fef4d1ec42f97b87c2721803946308b5a75d8947bb4d3de19b54f193b16e4cd913ecefd103c942e76f52cadaf0cc5853750317a94ae7902fc74de73cb754fa76dc6efaf469944a3ce7c3d28cbcf8c6cfac92d84d962d33df04f364b204fb3649f0b65843d5234c2857004a3944291e1602aef43019a46a92ef75ff8b82e67fab4fdc86b3c6f64d562a012b1c600924709b3c356009331e1bff97b90574bfe142f0d36b8bcde543290dd6a99e3faecf8edb1ade9e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85227);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-5359");
  script_bugtraq_id(75723);
  script_osvdb_id(124296);
  script_xref(name:"JSA", value:"JSA10687");

  script_name(english:"Juniper Junos BGP-VPLS Advertisements RPD DoS (JSA10687)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of BGP-VPLS advertisements with updated BGP local
preference values. A remote attacker can exploit this to crash RDP
with a NULL pointer deference exception.

Note that this issue only affects devices with internal BGP and VPLS
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10687");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10687.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R9';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2']    = '13.2R7';
fixes['13.3']    = '13.3R5';
fixes['14.1']    = '14.1R3-S2';
fixes['14.2']    = '14.2R2';
fixes['15.1']    = '15.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

#IBGP and VPLS must be configured
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Internal BGP (IBGP)
  pattern = "^set protocols bgp group \S+ type internal";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because internal BGP is not enabled');
  
  # Check that BGP-VPLS is configured
  buf = junos_command_kb_item(cmd:"show vpls connections");
  if (buf) 
  {
    pattern = "^BGP-VPLS State$";
    if (preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  }

  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
