#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59990);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/09/08 14:15:23 $");
  script_osvdb_id(85338);

  script_name(english:"Juniper Junos load factory-default Privilege Escalation (PSN-2012-07-646)");
  script_summary(english:"Checks model and version");

  script_set_attribute(attribute:"synopsis", value:"The remote device has a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
has a privilege escalation vulnerability. When the 'load
factory-default' command fails in exclusive edit mode, the user is no
longer subject to any command or configuration restrictions.");
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-07-646&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1dc2836c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-07-646.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:M/C:C/I:C/A:C");
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

fixes['10.0'] = '10.0S26';
fixes['10.4'] = '10.4R10';
fixes['11.2'] = '11.2R7';
fixes['11.3'] = '11.3R6';
fixes['11.4'] = '11.4R3';
fixes['12.1'] = '12.1R2';
fixes['12.1X44'] = '12.1X44-D15';
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
