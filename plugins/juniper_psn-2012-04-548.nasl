#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58877);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/08/28 13:51:52 $");
  script_osvdb_id(82821);

  script_name(english:"Juniper Junos SRX Series for the Data Center Memory Corruption (PSN-2012-04-548)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a memory corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version and model number, the version
of Junos running on the remote host has a memory corruption
vulnerability.  When an IPv6 flow session is freed on the Central
Point (CP), CP session statistics are updated.  In some situations
this update results in memory corruption.  It is not known if code
execution is possible."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-04-548&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?751c2070");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-04-548."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
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

fixes['10.4'] = '10.4R7';
fixes['11.1'] = '11.1R5';
fixes['11.2'] = '11.2R2';
fixes['11.4'] = '11.4R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# SRX Series for the Data Center (a subset of SRX Series) is affected
if (model != 'SRX1400' && model != 'SRX3400' && model != 'SRX3600' && model != 'SRX5600' && model != 'SRX5800')
  audit(AUDIT_HOST_NOT, 'SRX Series for the Data Center');

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

