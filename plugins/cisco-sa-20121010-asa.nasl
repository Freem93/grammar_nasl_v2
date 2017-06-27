#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62760);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id(
    "CVE-2012-4643",
    "CVE-2012-4659",
    "CVE-2012-4660",
    "CVE-2012-4661",
    "CVE-2012-4662",
    "CVE-2012-4663"
  );
  script_bugtraq_id(55861, 55862, 55863, 55864, 55865);
  script_osvdb_id(86137, 86144, 86145, 86146, 86147, 86148);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr21346");
  script_xref(name:"IAVA", value:"2012-A-0174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr21359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr21376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtr63728");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtw84068");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz04566");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121010-asa");

  script_name(english:"Cisco ASA 5500 Series Multiple Vulnerabilities (cisco-sa-20121010-asa)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and, therefore, may be
affected by the following issues :

  - A remote, unauthenticated attacker could cause a denial
    of service by sending specially crafted DHCP packets.
    (CVE-2012-4643)

  - When configured for Clientless or AnyConnect SSL VPN,
    receiving a specially crafted AAA response could cause
    a denial of service. (CVE-2012-4659)

  - A remote, unauthenticated attacker could cause a denial
    of service by sending a specially crafted SIP packet.
    (CVE-2012-4660)

  - A remote, unauthenticated attacker could execute
    arbitrary code by exploiting a stack-based buffer
    overflow in the DCERPC inspection engine.
    (CVE-2012-4661)

  - A remote, unauthenticated attacker could cause a
    denial of service by exploiting vulnerabilities in the
    DCERPC inspection engine.
    (CVE-2012-4662, CVE-2012-4663)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121010-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7164c1ce");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20121010-asa."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500');

# first check 7.0 and 7.1 (the recommendation is to migrate to 7.2 and upgrade)
if (ver =~ '^7\\.0($|[^0-9])' || ver =~ '^7\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 7.2(5.8)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The comparison is only made if the major versions match up
recommended_releases = make_list('7.2(5.8)', '8.0(5.28)', '8.1(2.56)', '8.2(5.30)', '8.3(2.34)', '8.4(4.4)', '8.5(1.13)', '8.6(1.5)');
foreach patch (recommended_releases)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);

