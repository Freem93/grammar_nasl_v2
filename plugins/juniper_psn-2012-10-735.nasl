#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62714);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/18 13:33:25 $");

  script_name(english:"Juniper Junos web-authentication Policy Not Enforced (PSN-2012-10-735)");
  script_summary(english:"Checks version and model");
  script_osvdb_id(86797);

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
stops enforcing a web-authentication policy if its client-match
statement is removed.  This would allow unauthenticated access to
resources that are assumed to be protected by web-authentication."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-10-735&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cbbaf129");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-10-735."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");

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

include("junos.inc");
include("misc_func.inc");

fixes['10.0'] = '10.0S27';
fixes['10.4'] = '10.4S9';
fixes['11.4'] = '11.4R1';
fixes['12.1'] = '12.1R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);
