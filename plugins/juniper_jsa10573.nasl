#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68906);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:40 $");

  script_cve_id("CVE-2013-4684");
  script_bugtraq_id(61127);
  script_osvdb_id(95107);

  script_name(english:"Juniper Junos SRX Series PIM DoS (JSA10573)");
  script_summary(english:"Checks the version, model, and build date");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability when
Protocol-Independent Multicast (PIM) is enabled. An attacker, using
specially crafted PIM packets subject to NAT, can cause the Flow
Daemon (flowd) to crash. Repeated flowd crashes can result in a
sustained denial of service against SRX series devices.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10573");
  script_set_attribute(attribute:"solution",value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10573.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-06-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes['10.4'] = '10.4S14';
fixes['11.4'] = '11.4R8';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D15';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_hole(port:0, extra:report);
}
else security_hole(0);

