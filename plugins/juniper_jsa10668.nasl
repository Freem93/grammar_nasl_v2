#TRUSTED 2e671441a4133c9be9fd6b9a808f187311018c9cdc42b5b81387d91498bd464998b6517601974ff3970c0329e45faf8cd83efcf73c19dd0935c0457eff32ca8c158d02c104ef8746b5f62151f00d9f365512c21e5afe9d67fd9d4cfb57d02eac44390888162e403ba302782b45ac0a754df7ff3212c9509bc59f4a3986bc205cd09af6c80eb9198f7cc5019419da74c43f3613e24e64887a446924e9dc6cd2b0d68395fef29cf697678831a3fdbd1ca2a81cf2f3c1d7014af338e64af2fc9c837194eb9dc928673647f8b5f12156ca7566c844ce64adf3599ab2ee521d4065efd726382ffcd4e7ec001f1584a2f6b919cd8690a24627bc577407576e8824b180a5ee11ff71d72fcc32b277714cad8e96be6effdc941086cea4c359ef5cebe61ec7fdb4fd1ce9d66ed01b5d0437fae74b7d868e1f95142a914dc885bf05fb6df416a1eaafcf25934e78624bf33029ddbd37576bc8fb0c073dbb8c1ae9536ab9610c8738a25c7868abe58090d1fb6a41210445e437b875b04a78eda05aa02fa0d6ca1af3728f2212cbbdd8c563243d717b7bfbadc6ba75492a09e8028a30287d54c072f9a8054ce4a4b5f17268c661e0958e382511870286c06d6d57e06b9c0f5a0222eb33e4c413171a1557787847cd05977c35c9b2a739e32b074bcafb8ae6db5fc5794c835909bfd24944fa2d7e037dd6deac82e965317481ad3abb1940e65f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80956);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/23");

  script_cve_id("CVE-2014-6385");
  script_bugtraq_id(72072);
  script_osvdb_id(117038);
  script_xref(name:"JSA", value:"JSA10668");

  script_name(english:"Juniper Junos Fragmented OSPFv3 Packet DoS (JSA10668)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability when
processing fragmented OSPFv3 packets with an IPsec Authentication
Header (AH). A remote attacker on an adjacent network can exploit
this issue to crash the kernel, resulting in the Routing Engine (RE)
restarting.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10668");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10668.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D15';
fixes['12.3']    = '12.3R9';
fixes['13.1']    = '13.1R4-S3';
fixes['13.2']    = '13.2R6';
fixes['13.3']    = '13.3R5';
fixes['14.1']    = '14.1R3';
fixes['14.2']    = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set protocols ospf area \S+ interface \S+ ipsec-sa \S+";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because OSPFv3 IPsec authentication is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
