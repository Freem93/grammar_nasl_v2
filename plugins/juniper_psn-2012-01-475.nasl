#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57639);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/18 13:33:24 $");

  script_osvdb_id(78851, 88406);

  script_name(english:"Juniper Junos BGP Multiple Remote DoS (PSN-2012-01-475)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote router has multiple denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Junos
running on the remote host has multiple denial of service
vulnerabilities.  Either of the following issues could result in an
rpd crash :

  - Receipt of a malformed non-transitive BGP PATH attribute

  - An established session disconnecting before BGP could
    send the first keepalive message

A remote attacker could exploit this to crash the rpd service."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-01-475&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?134038d1");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-01-475."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
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

fixes['9.3'] = '9.3S18';
fixes['10.0'] = '10.0S15';
fixes['10.2'] = '10.2R4';
fixes['10.3'] = '10.3R3';
fixes['10.4'] = '10.4R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:ALL_ROUTERS, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

