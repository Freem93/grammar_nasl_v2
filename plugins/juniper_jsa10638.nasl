#TRUSTED 4f753f4a2fbc733562b494c980fbd118b31ab4e28590f4db11b907620b6205478cf943333b0d690bae4974ce6717c3b1563453299e83bfb4f933d1db53bab1123c0d7b1c3f8975232e2e38c6e274aa983e3dcaf75e98212fb4dd003c88ea2a6beaf5cd49df93d4e53d91f1c9774cca06ef1a9e78f70b898e820ad10c46878706dd1caa1c8475935702cf5165d12b9216c0a73fd7c2aa8cea8393ead2c711e35cd28a62dbcfcdc9e2aa2f28a2bfcee4b6f177f06e077bab7ef3e7ec4de9477ca04fcddbd6b73c87c693e0951789562a473333b1e43ac44c95f1bfa4c29720a2732f4ffbc9c39b75efdb3da705f0c0646a9947c2c9cd876478418feade7f90e150fa2eacff4d6ea64715a4cbb017d3f27b5fe2a1c3ef797298557e68642c435c315ce6fc39932f228f8b3a993c4b76ba0786e5ab4398b2759d21f7cd34212aa55463bb67a7e363807a6fd5354763f66e625fccb8e73d20159005680ac4b1dcbaa9f125562456555d2ab3b415aa70b8f26191d526c2b6d1d29608e195912a34c08fd7bc8bfd6e87bda3e2a12c44a12d30a056402d16d5c981d5e45267377cff0dbf404891232cb9556e35f7998b62162dfde4f1c46b8a735bfd8da47a8a9d8fb599e58cc359d3462b3455464c6459639377876abce71855fc415818cc48b3cf44369f30efc6ca7cb75d307cccfae76afede00f05a3f49f5130f0bc8a80b8b35b846
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76506);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2004-0230");
  script_bugtraq_id(10183);
  script_osvdb_id(4030);
  script_xref(name:"JSA", value:"JSA10638");

  script_name(english:"Juniper Junos TCP Packet Processing Remote DoS (JSA10638)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. An
attacker who can guess an in-window sequence number, source and
destination addresses, and port numbers can exploit this vulnerability
to reset any established TCP session.

This issue only affects TCP sessions terminating on the router.
Transit traffic and TCP Proxy services are unaffected by this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10638");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10638.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver        = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-26') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.1']    = '12.1R10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
# Multiple workarounds are available but all other workarounds are difficult to check
if (buf)
{
  pattern = "^set system internet-options tcp-reset-syn-acknowledge";
  if (junos_check_config(buf:buf, pattern:pattern))
    override = FALSE;
  # Display caveat instead of checking for other workarounds/auditing out
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
