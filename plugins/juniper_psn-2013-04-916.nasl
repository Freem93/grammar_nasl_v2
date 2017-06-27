#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66514);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/10/18 13:33:25 $");

  script_bugtraq_id(60014);
  script_osvdb_id(92222);

  script_name(english:"Juniper Junos Invalid Ether-type DoS (PSN-2013-04-916)");
  script_summary(english:"Checks version, model, and build date");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has a denial of service vulnerability.  Receiving Ethernet packets with
an invalid Ether-type can cause congestion on routers with line cards
installed using Ichip-based FPCs and DPCs.  An unauthenticated attacker
on the same subnet could exploit this, causing the router to drop valid
protocol traffic."
  );
  # http://www.juniper.net/alerts/viewalert.jsp?actionBtn=Search&txtAlertNumber=PSN-2013-04-916&viewMode=view
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c587c6c");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2013-04-916."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-03-18') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '12.1R5-S1' || ver == '12.2R3-S1' || ver == '12.3R1-S1')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes['10.4'] = '10.4S13';
fixes['11.4'] = '11.4R7';
fixes['11.4X'] = '11.4X27.37';
fixes['12.1'] = '12.1R6';
fixes['12.2'] = '12.2R4';
fixes['12.3'] = '12.3R2';
fixes['13.1'] = '13.1R1';

# MX Series are affected, as are the M120 and M320
if (
  !check_model(model:model, flags:MX_SERIES) &&
  model != 'M120' &&
  model != 'M320'
)
{
  audit(AUDIT_HOST_NOT, 'MX Series, M120, or M320');
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

