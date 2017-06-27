#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59996);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");
  script_osvdb_id(85335);

  script_name(english:"Juniper Junos UDP/IP DoS (PSN-2012-07-652)");
  script_summary(english:"checks model and version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos
device has a denial of service vulnerability.  The flowd process may
crash when reassembling UDP/IP fragments."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-652&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8dee580");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-652."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");
include("audit.inc");

fixes['10.0'] = '10.0S26';
fixes['10.4'] = '10.4S7';
fixes['11.2'] = '11.2R1';
fixes['11.3'] = '11.3R1';

# From the advisory:
#
# Note that the SRX 100, 110, 210 and 220 services gateways for the Branch and the J Series
# services gateway all use a single data thread and are not affected by this vulnerability.
model = get_kb_item_or_exit('Host/Juniper/model');
check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);
if (model =~ '^SRX1[01]0' || model =~ '^SRX2[12]0')
  audit(AUDIT_HOST_NOT, 'an affected SRX series model');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);
