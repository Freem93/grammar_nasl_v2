#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66336);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_osvdb_id(89751);

  script_name(english:"Juniper Junos Unspecified DoS (PSN-2013-01-818)");
  script_summary(english:"Checks version and model");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has an unspecified denial of service vulnerability.  A remote,
unauthenticated attacker could exploit this by sending a specially
crafted TCP packet, causing the host to crash."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?txtAlertNumber=PSN-2013-01-818
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2218fb22");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=KB21476");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2013-01-823."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/07");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");
include("audit.inc");

build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');
model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# All Junos OS software releases built on or after 2013-01-17 have fixed this specific issue
if (compare_build_dates(build_date, '2013-01-17') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

# multiple fixes are listed for 11.4. the plugin will account for this by considering
# all 11.4 releases prior to the highest version (11.4R7.5) to be vulnerable (see below)
# _unless_ the build date indicates it isn't (see above) or the current version is any
# of the other, lower fixes for 11.4
if (
  ver == '11.4R4.4' ||  # source - KB21476
  ver == '11.4R5.7' ||  # source - KB21476
  ver == '11.4R6-S1'    # source - PSN-2013-01-823
)
{
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
}

fixes['10.4'] = '10.4S12';  # source - PSN-2013-01-823
fixes['11.4'] = '11.4R7.5'; # source - KB21476
fixes['12.1'] = '12.1R4';   # source - PSN-2013-01-823
fixes['12.2'] = '12.2R2';   # source - PSN-2013-01-823
fixes['12.3'] = '12.3R1';   # source - PSN-2013-01-823
fixes['12.2X50'] = '12.2X50-D41.1';  # source - KB21476

check_model(model:model, flags:ALL_ROUTERS, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);
