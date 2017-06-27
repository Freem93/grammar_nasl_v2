#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68912);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:40 $");

  script_cve_id(
    "CVE-2003-0001", # generic etherleak vulnerability
    "CVE-2013-4690"  # etherleak in junos
  );
  script_bugtraq_id(
    6535, # generic etherleak vulnerability
    61123 # etherleak in junos
  );
  script_osvdb_id(
    3873, # generic etherleak vulnerability
    95112 # etherleak in junos
  );
  script_xref(name:"CERT", value:"412115"); # generic etherleak vulnerability

  script_name(english:"Juniper Junos SRX1400/3400/3600 Etherleak Information Disclosure (JSA10579)");
  script_summary(english:"Checks version, model, and build date");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has an information disclosure vulnerability.  SRX1400, SRX3400, and
SRX3600 services gateways pad Ethernet packets with data from previous
packets instead of padding them with null bytes.  A remote,
unauthenticated attacker could exploit this to gain access to sensitive
information, which could be used to mount further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"https://lkml.org/lkml/2002/4/27/101");
  script_set_attribute(attribute:"see_also", value:"http://blog.spoofed.org/2007/03/etherleak-old-dog-old-tricks.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10579");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
JSA10579."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/27"); # disclosed on LKML
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

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (model != 'SRX1400' && model != 'SRX3400' && model != 'SRX3600')
  audit(AUDIT_HOST_NOT, 'SRX1400/3400/3600');
if (compare_build_dates(build_date, '2013-06-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');
if (ver == '11.4R7-S1' || ver == '12.1R5-S3')
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes['10.4'] = '10.4S13';
fixes['11.4'] = '11.4R8';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_warning(port:0, extra:report);
}
else security_warning(0);

