#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62713);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 11:04:02 $");

  script_name(english:"Juniper Junos BGP UPDATE DoS (PSN-2012-10-733)");
  script_summary(english:"Checks version and model");
  script_osvdb_id(86796);

  script_set_attribute(attribute:"synopsis", value:"The remote device has a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
could crash when processing a BGP UPDATE message containing a
specially crafted flow specification NLRI. A remote attacker could
exploit this to cause a denial of service.");
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-10-733&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf463008");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-10-733.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

fixes['10.0'] = '10.0S28';
fixes['10.4'] = '10.4R11';
fixes['11.4'] = '11.4R5';
fixes['12.1'] = '12.1R3';
fixes['12.2'] = '12.2R1';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D10';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);
