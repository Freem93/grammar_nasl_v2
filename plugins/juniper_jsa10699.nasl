#TRUSTED 6257a82928d062f8d087792d33e2908b608ed942a3156c0610d1fa7e5578d7a6e2565aab6d03b6dc771fa0866a9994674bc45707ead00c132828b6344ebb302f84b6f0d88f14c9a379deb2c111c10f8895dff70d3c1454f5ff32dca8f3705174fef23f510eed0983cd20c0675e5205ff8f4dcf6350bd9b52c6cbc262c16887bb1192f885362ad6c10ab03219c8a96975b9ee832b8972f88a6a130d0ed63e44f837dce9efd2d1ead493842dad6d3c96f31c96e9bf508c036ace8a70917244cc95c636edd43af815606f2c33efa3e158a6dd1453383bae5cbf16888ef29b48c98e789c4e1c7e80958f0fad47bee963321ca0ffe6b113f21aec8a7145d8870d8b07afac769ca274f7848423106faab1b9e50276595a68b8824b76214f06345578c01e27a8e77259cfb2a1d1c781f276878ff92f8fcc9d6dd2fbc7e5791d0cfea29bdce93d4b716cd705de0dfebf4c6fdfecd99876e1de2d24f569c9290fc951f638d89c587b0517d3d9bfa835d5ba8a1e15cc80b3a3ea06a83e100cd199abc17091cbba2f1b062345fade8148b7cc27da5d9cce83dccfab0f16b93460bc523e51adf0ad922fc5d00c60e75a89b011a6e4ca4efbef73fab994c7f06a9af6669e331cb8c2b884268774656409d9fa99bc48f46b9eff4d8440a1ceac8a8f80cf4044fe6b2d03b4b0b2d7c6a1106bb0d774c0b6ee14594e90676cc1f2e3c0b207979bd3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86476);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6450");
  script_bugtraq_id(77125);
  script_osvdb_id(128900);
  script_xref(name:"JSA", value:"JSA10699");

  script_name(english:"Juniper Junos IPv6 Packet Handling mbuf Chain Corruption DoS (JSA10699)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to a
flaw related to the processing of IPv6 packets. An unauthenticated,
remote attacker can exploit this, via a specially crafted IPv6 packet,
to trigger an 'mbuf' chain corruption, resulting in a kernel panic and
a denial of service condition.

Note that this issue only affects devices with IPv6 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10699");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10699.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

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
fixes['11.4'   ] = '11.4R12-S4';  # or 11.4R13
fixes['12.1X44'] = '12.1X44-D41';
fixes['12.1X46'] = '12.1X46-D26';
fixes['12.1X47'] = '12.1X47-D11'; # or 12.1X47-D15
fixes['12.2'   ] = '12.2R9';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3'   ] = '12.3R8';
fixes['12.3X48'] = '12.3X48-D10';
fixes['12.3X50'] = '12.3X50-D42';
fixes['13.1'   ] = '13.1R4-S3';   # or 13.1R5
fixes['13.1X49'] = '13.1X49-D42';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2'   ] = '13.2R6';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3'   ] = '13.3R3-S3';   # or 13.1R4
fixes['14.1'   ] = '14.1R3';
fixes['14.2'   ] = '14.2R1';
fixes['15.1'   ] = '15.1R1';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if(fix == '11.4R12-S4')
  fix += ' or 11.4R13';
if(fix == '12.1X47-D11')
  fix += ' or 12.1X47-D15';
if(fix == '13.1R4-S3')
  fix += ' or 13.1R5';
if(fix == '13.3R3-S3')
  fix += 'or 13.1R4';

# Check if IPv6 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces .* family inet6 ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
