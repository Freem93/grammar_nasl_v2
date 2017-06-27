#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71310);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:35:40 $");

  script_cve_id("CVE-2013-6618");
  script_bugtraq_id(62305);
  script_osvdb_id(92227);
  script_xref(name:"EDB-ID", value:"29544");

  script_name(english:"Juniper Junos J-Web Sajax Remote Code Execution (JSA10560)");
  script_summary(english:"Checks the version and build date.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a remote code execution vulnerability due to a lack of
validation when passing input from the 'rs' parameter to the
'/jsdm/ajax/port.php' script. Authenticated users, when J-Web is
enabled, can execute arbitrary commands with administrative
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10560");
  script_set_attribute(attribute:"see_also", value:"http://www.senseofsecurity.com.au/advisories/SOS-13-003");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos upgrade or the workaround referenced in
Juniper advisory JSA10560.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

# Requires J-Web be enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

date_cmp = compare_build_dates(build_date, '2013-02-28');

if (date_cmp >= 0) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes['10.4'] = '10.4R13';
fixes['11.4'] = '11.4R7';
fixes['12.1'] = '12.1R5';
fixes['12.2'] = '12.2R3';
fixes['12.1X44'] = '12.1X44-D15';
fixes['12.1X45'] = '12.1X45-D10';
fixes['12.3'] = '12.3R1';
fixes['13.2'] = '13.2R6';
fixes['13.2X51'] = '13.2X51-D25';
fixes['13.3'] = '13.3R4';
fixes['14.1'] = '14.1R3';
fixes['14.2'] = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes);

if (isnull(fix))
{
  foreach fixed_ver (fixes)
    if (ver == fixed_ver) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
  fix = "Please refer to the vendor for a solution.";
}

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Build date        : ' + build_date +
    '\n  Fixed version     : ' + fix + 
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
