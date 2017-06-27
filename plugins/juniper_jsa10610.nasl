#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71999);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:40 $");

  script_cve_id("CVE-2014-0617");
  script_bugtraq_id(64764);
  script_osvdb_id(101863);
  script_xref(name:"JSA", value:"JSA10610");

  script_name(english:"Juniper Junos SRX Series flowd Remote DoS (JSA10610)");
  script_summary(english:"Checks the version, model, and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a denial of service vulnerability in the flow daemon
(flowd). A remote attacker can exploit this, via crafted IP packets,
to crash the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10610");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10610.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (
  model != 'SRX100' &&
  model != 'SRX110' &&
  model != 'SRX210' &&
  model != 'SRX220' &&
  model != 'SRX240' &&
  model != 'SRX550' &&
  model != 'SRX650'
) audit(AUDIT_HOST_NOT, 'a SRX Series for a branch device');

if (compare_build_dates(build_date, '2013-12-11') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4S15';
fixes['11.4'] = '11.4R9';
fixes['12.1'] = '12.1R7';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_hole(port:0, extra:report);
}
else security_hole(0);
