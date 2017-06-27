#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55940);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(77146);

  script_name(english:"Juniper Junos debug.php J-Web Component Unauthenticated Debug Access (PSN-2011-02-158)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has debugging features enabled."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote device
is running a version of Junos with a vulnerable J-Web component.
The 'debug.php' file was inadvertently included with this Junos
release.  This file enables unspecified debugging functions and output.

A remote, unauthenticated attacker could exploit this to have
unspecified impact on confidentiality and integrity."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?464bac18");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-02-158."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['8.1'] = '8.1R4.2';
fixes['8.5'] = '8.5S1';
fixes['9.0'] = '9.0S1';
fixes['9.3'] = '9.3R2';
fixes['9.4'] = '9.4R3';
fixes['9.5'] = '9.5R2.4';
fixes['9.6'] = '9.6R4';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:SRX_SERIES | MX_SERIES | EX_SERIES | J_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

