#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70477);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:35:40 $");

  script_cve_id("CVE-2013-6170");
  script_bugtraq_id(62973);
  script_osvdb_id(89476, 98367);

  script_name(english:"Juniper Junos PIM Remote Denial of Service (JSA10548)");
  script_summary(english:"Checks version and build date");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
has a denial of service vulnerability.  A flaw in the way in which the
Next-Generation Multicast VPN (NGEN MVPN) environment process large
numbers of specifically crafted PIM join messages can cause the RPD
routing daemon to crash."
  );
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10548");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
JSA10548."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2012-09-27') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes['10.0'] = '10.0S28';
fixes['10.4'] = '10.4R7';
fixes['11.1'] = '11.1R5';
fixes['11.2'] = '11.2R2';
fixes['11.4'] = '11.4R1';
fix = check_junos(ver:ver, fixes:fixes);

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_warning(port:0, extra:report);
}
else security_warning(0);
