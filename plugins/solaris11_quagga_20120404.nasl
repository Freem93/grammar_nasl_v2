#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80751);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2007-4826", "CVE-2009-1572", "CVE-2010-1674", "CVE-2010-1675", "CVE-2010-2948", "CVE-2010-2949", "CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326");

  script_name(english:"Oracle Solaris Third-Party Patch Update : quagga (multiple_denial_of_service_vulnerabilities4)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - bgpd in Quagga before 0.99.9 allows explicitly
    configured BGP peers to cause a denial of service
    (crash) via a malformed (1) OPEN message or (2) a
    COMMUNITY attribute, which triggers a NULL pointer
    dereference. NOTE: vector 2 only exists when debugging
    is enabled. (CVE-2007-4826)

  - The BGP daemon (bgpd) in Quagga 0.99.11 and earlier
    allows remote attackers to cause a denial of service
    (crash) via an AS path containing ASN elements whose
    string representation is longer than expected, which
    triggers an assert error. (CVE-2009-1572)

  - The extended-community parser in bgpd in Quagga before
    0.99.18 allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a malformed Extended Communities attribute.
    (CVE-2010-1674)

  - bgpd in Quagga before 0.99.18 allows remote attackers to
    cause a denial of service (session reset) via a
    malformed AS_PATHLIMIT path attribute. (CVE-2010-1675)

  - Stack-based buffer overflow in the
    bgp_route_refresh_receive function in bgp_packet.c in
    bgpd in Quagga before 0.99.17 allows remote
    authenticated users to cause a denial of service (daemon
    crash) or possibly execute arbitrary code via a
    malformed Outbound Route Filtering (ORF) record in a BGP
    ROUTE-REFRESH (RR) message. (CVE-2010-2948)

  - bgpd in Quagga before 0.99.17 does not properly parse AS
    paths, which allows remote attackers to cause a denial
    of service (NULL pointer dereference and daemon crash)
    via an unknown AS type in an AS path attribute in a BGP
    UPDATE message. (CVE-2010-2949)

  - The OSPFv3 implementation in ospf6d in Quagga before
    0.99.19 allows remote attackers to cause a denial of
    service (out-of-bounds memory access and daemon crash)
    via a Link State Update message with an invalid IPv6
    prefix length. (CVE-2011-3323)

  - The ospf6_lsa_is_changed function in ospf6_lsa.c in the
    OSPFv3 implementation in ospf6d in Quagga before 0.99.19
    allows remote attackers to cause a denial of service
    (assertion failure and daemon exit) via trailing zero
    values in the Link State Advertisement (LSA) header list
    of an IPv6 Database Description message. (CVE-2011-3324)

  - ospf_packet.c in ospfd in Quagga before 0.99.19 allows
    remote attackers to cause a denial of service (daemon
    crash) via (1) a 0x0a type field in an IPv4 packet
    header or (2) a truncated IPv4 Hello packet.
    (CVE-2011-3325)

  - The ospf_flood function in ospf_flood.c in ospfd in
    Quagga before 0.99.19 allows remote attackers to cause a
    denial of service (daemon crash) via an invalid Link
    State Advertisement (LSA) type in an IPv4 Link State
    Update message. (CVE-2011-3326)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_vulnerabilities4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5437d247"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_vulnerabilities5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e395ea1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:quagga");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^quagga$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.4.0.5.0", sru:"SRU 4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : quagga\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "quagga");
