#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59997);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");
  script_osvdb_id(85334);

  script_name(english:"Juniper Junos host-inbound-traffic Implicit Allow (PSN-2012-07-653)");
  script_summary(english:"checks version and model");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device does not properly enforce access control rules."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos
device allows inbound SSH traffic even when 'host-inbound-traffic' is
not explicitly configured to allow it."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-653&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf717656");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-653."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
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

fixes['10.4'] = '10.4R10';
fixes['11.2'] = '11.2R7';
fixes['11.4'] = '11.4R4';
fixes['12.1'] = '12.1R2';

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
