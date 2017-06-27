#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62711);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/18 13:33:25 $");

  script_name(english:"Juniper Junos ttymodem() DoS (PSN-2012-08-699)");
  script_summary(english:"Checks version and model");
  script_osvdb_id(86798);

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has a denial of service vulnerability.  A timing issue in ttymodem() can
cause the Junos kernel to crash whenever the device is accessed remotely
(e.g., telnet, SSH)."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2012-08-699&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?443c491a");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2012-08-699."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/15");
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

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

# the advisory explicitly lists vulnerable versions
# key = vulnerable version, value = version to upgrade to
fixes['11.4R2'] = '11.4R4';
fixes['11.4R3'] = '11.4R4';
fixes['11.4R3-S1'] = '11.4R4';
fixes['11.4R3-S2'] = '11.4R4';
fixes['12.1R2'] = '12.1R3';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fix = fixes[ver];

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

if (report_verbosity > 0)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
