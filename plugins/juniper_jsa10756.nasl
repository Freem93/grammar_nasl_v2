#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92514);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/27 19:44:38 $");

  script_cve_id("CVE-2009-1436");
  script_bugtraq_id(34666);
  script_osvdb_id(53918);
  script_xref(name:"JSA", value:"JSA10756");

  script_name(english:"Juniper Junos FreeBSD libc db Information Disclosure (JSA10756)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an information disclosure vulnerability in
the underlying FreeBSD operating system libc db interface due to
improper initialization of memory for Berkeley DB 1.85 database
structures. A local attacker can exploit this to disclose sensitive
information by reading a database file.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10756");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10756.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/22");
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

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D40';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3X48'] = '12.3X48-D20';
fixes['12.3X50'] = '12.3X50-D50';
fixes['12.3'] = '12.3R11';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.2X52'] = '13.2X52-D30';
fixes['13.2'] = '13.2R8';
fixes['13.3'] = '13.3R7';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.1'] = '14.1R6';
fixes['14.2'] = '14.2R4';
fixes['15.1X49'] = '15.1X49-D10'; # or 15.1X49-D20
fixes['15.1R'] = '15.1R2';
fixes['15.1F'] = '15.1F3';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix ==  "15.1X49-D10")
  fix += " or 15.1X49-D20";

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
