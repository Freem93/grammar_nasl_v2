#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56771);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");
  script_osvdb_id(77154);

  script_name(english:"Juniper Junos J-Web Administrator Logs XSS (PSN-2011-10-392)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the J-Web component of
the remote Juniper device has a persistent cross-site scripting
vulnerability.  During the authentication process, user controlled
input is added to the administrator logs.  When an administrator
reviews the logs, that user controlled input is displayed without
being sanitized, which could result in a cross-site scripting attack."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2011-10-392&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1015579");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-10-392."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = NULL;

# 9.3S21 (J Series)
if (check_model(model:model, flags:J_SERIES))
{
  fixes['9.3'] = '9.3S21';
  fix = check_junos(ver:ver, fixes:fixes);
}

# 9.3S22 (M/T)
if (isnull(fix) && check_model(model:model, flags:M_SERIES | T_SERIES))
{
  fixes['9.3'] = '9.3S22';
  fix = check_junos(ver:ver, fixes:fixes);
}

# check everything else
if (isnull(fix))
{
  fixes = NULL;
  fixes['10.0'] = '10.0S17';
  fixes['10.4'] = '10.4R6';
  fixes['11.1'] = '11.1R3';
  fixes['11.2'] = '11.2R1';

  check_model(model:model, flags:SRX_SERIES | MX_SERIES | EX_SERIES | J_SERIES | T_SERIES | M_SERIES, exit_on_fail:TRUE);
  fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
}

if (isnull(fix))
  exit(0, 'Junos version ' + ver + ' (model ' + model + ' is not affected.');

set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

