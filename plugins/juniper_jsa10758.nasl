#TRUSTED aceb7fdd91a2a671f998b7d724ec22e800ae7056f64da119f239ff9c669e7421993a0c3a90ffcf8896abd115078cf8e743b9bb5ebb5a5402771e25b477f0154d44d567c192c1c4b7feead47600923554596bff9c15a010690a3dbedfb4b17c3e060c27cca4014081069b2d48118665c5935413184fd9eca8adf29d59218309d4700d65b8f1f3d3173f9655238e18e8d0cfd06c2ed6587d72de46643c30ea78e99a8bbc1c448085a67ceec98ac838b54573dc9561688e48398566f377f335fcb6850e5835e4f4cff0bbcbcaae5dfec5ae6bcacb974ed4e3f34ae768cedf7cbcf06292b3bf6a0944c6cce653a419a9cbafd2860fb10cd21e6a1c2584e02302511d7aa41e089048bd4f2b67799b8a02a2989121d662de4ffa7415f004ed28dc41ac53e71354c6add3d7640c53dd0e27c21f264afd8e2fed8a7c02daf3814420b11e65711d78cbf821d42d4827e81fe08653753f5810155c749788f3fc1e832a7de485deb5a026e93a7be3ecd802834e8061800420d83d6c71254f8e1907791a4f115a68264f05801d8c5404ee94bb4222877f4acb66899d9cb09fbde7b0c1c0345714dc706eb91639ac1c0451e7e20aa766dc5f153b39e978bd9d96ba3fa5a140a79429752a1a9ffc583f8f86a0922904147d6fa7f11acef9293431ec6e3f84b5053f8abebedffd6f36dc880119cdc7e87962c57af8db1e5f4f714c584a119d51ce
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92515);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/27");

  script_cve_id("CVE-2016-1263");
  script_bugtraq_id(91763);
  script_osvdb_id(141473);
  script_xref(name:"JSA", value:"JSA10758");

  script_name(english:"Juniper Junos Crafted UDP Packet Handling DoS (JSA10758)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and architecture, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the 64-bit routing engine. An unauthenticated, remote
attacker can exploit this, via a specially crafted UDP packet sent to
an interface IP address, to crash the kernel. Note that this
vulnerability does not affect 32-bit systems.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10758");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10758.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D45'; # or 12.1X46-D51
fixes['12.1X47'] = '12.1X47-D35';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.3'] = '13.3R9-S1'; # or 13.3R10
fixes['14.1'] = '14.1R7';
fixes['14.2'] = '14.2R6';
fixes['15.1F'] = '15.1F2-S5'; # or 15.1F4-S2 or 15.1F5
fixes['15.1R'] =  '15.1R2-S3'; # or 15.1R3
fixes['15.1X49'] = '15.1X49-D40';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.1X46-D45")
  fix += " or 12.1X46-D51";
if (fix == "13.3R9-S1")
  fix += " or 13.3R10";
if (fix == "15.1F2-S5")
  fix += " or 15.1F4-S2 or 15.1F5";
if (fix == "15.1R2-S3")
  fix += " or 15.1R3";

override = TRUE;
buf = junos_command_kb_item(cmd:"show version detail | match 64");
if (buf)
{
  pattern = "^JUNOS 64-bit Kernel";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because a 64-bit kernel is not in use');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
