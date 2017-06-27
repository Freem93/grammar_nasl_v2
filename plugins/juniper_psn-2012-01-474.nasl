#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57638);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");
  script_osvdb_id(78850);

  script_name(english:"Juniper Junos J-Web Component Unspecified CSRF (PSN-2012-01-474)");
  script_summary(english:"Checks version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a cross-site request forgery vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the J-Web component of
the remote Juniper device has a cross-site request forgery
vulnerability.  A remote attacker could exploit this by tricking a
user into making a maliciously crafted request, resulting in a
compromise of the device."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd94b3a6");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-01-474."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/11");
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

fixes['10.4'] = '10.4R7';
fixes['11.1'] = '11.1R5';
fixes['11.2'] = '11.2R3';
fixes['11.3'] = '11.3R2';
fixes['11.4'] = '11.4R1';

# there's no need to check the model since everything with j-web is affected,
# but it's pulled from the KB anyway since it's used in the report
model = get_kb_item('Host/Juniper/model');
if (isnull(model)) model = 'n/a';
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

set_kb_item(name:'www/0/XSRF', value:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

