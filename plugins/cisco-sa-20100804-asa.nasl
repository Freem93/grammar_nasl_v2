#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(56045);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");
 
  script_cve_id(
    "CVE-2010-1578",
    "CVE-2010-1579",
    "CVE-2010-1580",
    "CVE-2010-1581",
    "CVE-2010-2814",
    "CVE-2010-2815",
    "CVE-2010-2816",
    "CVE-2010-2817"
  );
  script_bugtraq_id(
    42187,
    42188,
    42189,
    42190,
    42192,
    42195,
    42196,
    42198
  );
  script_osvdb_id(67007, 67008, 67009, 67010, 67012, 67013, 67014, 67015);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc77567");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc79922");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtc85753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd32106");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtd32627");
  script_xref(name:"CISCO-BUG-ID", value:"CSCte46507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf37506");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtf55259");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20100804-asa");

  script_name(english:"Cisco ASA 5500 Series Multiple DoS Vulnerabilities (cisco-sa-20100804-asa)");
  script_summary(english:"Checks the version of the remote ASA.");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"The remote security device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and may be vulnerable
to the following issues :

  - Multiple DoS vulnerabilities in the SunRPC inspection
    engine that can be triggered by sending unspecified
    UDP packets.
    (CVE-2010-1578, CVE-2010-1579, CVE-2010-1580)

  - Multiple TLS DoS vulnerabilities.  Devices configured
    for SSL VPN, TLS Proxy for Encrypted Voice Inspection,
    or ASDM management connections are vulnerable.
    (CVE-2010-1581, CVE-2010-2814, CVE-2010-2815)

  - A DoS vulnerability in the SIP inspection engine.
    (CVE-2010-2816)

  - An unspecified DoS vulnerability in the IKE implementation.
    (CVE-2010-2817)

A remote, unauthenticated attacker could cause the device to
reload by exploiting any of these issues."
  );
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?75808346");
  # http://www.cisco.com/en/US/products/products_security_advisory09186a0080b3f12f.shtml
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?54bb11ba");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate Cisco ASA patch (see plugin output)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/08/04");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/08/04");
  script_set_attribute(attribute:"plugin_publication_date",value:"2011/09/01");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();
  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");
 
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

# first check 7.1 (the recommendation is to migrate to 7.2 and upgrade)
if (ver =~ '^7\\.1($|[^0-9])')
{
  report =
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : 7.2(5)\n';
  security_hole(port:0, extra:report);
  exit(0);
}

# compare the ASA version versus all recommended releases.  The
# comparison is only made if the major versions match up
recommended_releases = make_list('7.0(8.11)', '7.2(5)', '8.0(5.19)', '8.1(2.47)', '8.2(2.17)', '8.3(1.6)');
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

