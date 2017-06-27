#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65931);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id(
    "CVE-2013-1149",
    "CVE-2013-1150",
    "CVE-2013-1151",
    "CVE-2013-1152"
  );
  script_bugtraq_id(59001, 59004, 59005, 59012);
  script_osvdb_id(92208, 92209, 92210, 92211);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub85692");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc72408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc80080");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud16590");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130410-asa");

  script_name(english:"Cisco ASA Multiple Vulnerabilities (cisco-sa-20130410-asa)");
  script_summary(english:"Check ASA model and version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host (Cisco ASA 5500 series or 1000V Cloud Firewall) is
missing a security patch.  It, therefore, could be affected by the
following issues :

  - An unspecified vulnerability in the IKE version 1
    implementation. (CVE-2013-1149)

  - An unspecified vulnerability in the URL processing code
    of the authentication proxy feature. (CVE-2013-1150)

  - An unspecified vulnerability in the implementation to
    validate digital certificates. (CVE-2013-1151)

  - An unspecified vulnerability in the DNS inspection
    engine. (CVE-2013-1152)

A remote, unauthenticated attacker could exploit any of these
vulnerabilities to cause a device reload."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130410-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c7d11a4");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130410-asa."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]' && model != '1000V')
  audit(AUDIT_HOST_NOT, 'ASA 5500 or 1000V');

# for 7.0 and 7.1 the recommendation is to migrate to 7.2 and upgrade
if (ver =~ '^7\\.0($|[^0-9])' || ver =~ '^7\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 7.2.x (7.2(5.10) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# for 8.1 the recommendation is to migrate to 8.2 and upgrade
if (ver =~ '^8\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 8.2.x (8.2(5.38) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# for 8.5 the recommended fix for CSCud16590 is to migrate to 9.x and upgrade
if (ver =~ '^8\\.5($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : migrate to 9.x (9.0(1.2) / 9.1(1.2) or later)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all fixed releases.  The comparison is only made if the major versions match up
fixed_releases = make_list(
  '7.2(5.10)',
  '8.0(5.31)',
  '8.2(5.38)',
  '8.3(2.37)',
  '8.4(5.3)',
  '8.6(1.10)',
  '8.7(1.4)',
  '9.0(1.2)',
  '9.1(1.2)'
);
foreach fix (fixed_releases)
{
  if (check_asa_release(version:ver, patched:fix))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);
