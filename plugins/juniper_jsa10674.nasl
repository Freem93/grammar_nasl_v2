#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82795);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2015-3003");
  script_bugtraq_id(74023);
  script_osvdb_id(120481);

  script_name(english:"Juniper Junos Multiple Privilege Escalation Vulnerabilities (JSA10674)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by privilege escalation vulnerabilities due
to flaws in various combination of CLI commands and arguments. A local
attacker can use these to gain root access to the operating system and
thus completely control the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10674");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10674.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

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
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3'] = '12.3R9';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2'] = '13.2R6';
fixes['13.3'] = '13.3R5';
fixes['14.1'] = '14.1R3';
fixes['14.2'] = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_warning(port:0, extra:report);
}
else security_warning(0);
