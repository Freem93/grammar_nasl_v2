#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57636);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(78848);

  script_name(english:"Juniper Junos MGD-CLI Arbitrary Command Execution (PSN-2011-11-418)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has an arbitrary command execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Junos
running on the remote device has a command execution vulnerability.  A
flaw in the logical model governing inter-process communications
between the management daemon (MGD) and the command-line interpreter
(CLI) could result in arbitrary command execution.

A local attacker could exploit this to completely compromise the
device."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82438147");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-11-418."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['9.3'] = '9.3S20';
fixes['10.0'] = '10.0S13';
fixes['10.2'] = '10.2R4';
fixes['10.3'] = '10.3R4';
fixes['10.4'] = '10.4R3';
fixes['11.1'] = '11.1R1';
fixes['11.2'] = '11.2R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:MX_SERIES | J_SERIES | M_SERIES | SRX_SERIES | EX_SERIES | T_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

