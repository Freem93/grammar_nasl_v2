#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80805);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-3548", "CVE-2012-5237", "CVE-2012-5238", "CVE-2012-5239", "CVE-2012-5240");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark4)");
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

  - The dissect_drda function in
    epan/dissectors/packet-drda.c in Wireshark 1.6.x through
    1.6.10 and 1.8.x through 1.8.2 allows remote attackers
    to cause a denial of service (infinite loop and CPU
    consumption) via a small value for a certain length
    field in a capture file. (CVE-2012-3548)

  - The dissect_hsrp function in
    epan/dissectors/packet-hsrp.c in the HSRP dissector in
    Wireshark 1.8.x before 1.8.3 allows remote attackers to
    cause a denial of service (infinite loop) via a
    malformed packet. (CVE-2012-5237)

  - epan/dissectors/packet-ppp.c in the PPP dissector in
    Wireshark 1.8.x before 1.8.3 uses incorrect OUI data
    structures during the decoding of (1) PPP and (2) LCP
    data, which allows remote attackers to cause a denial of
    service (assertion failure and application exit) via a
    malformed packet. (CVE-2012-5238)

  - Buffer overflow in the dissect_tlv function in
    epan/dissectors/packet-ldp.c in the LDP dissector in
    Wireshark 1.8.x before 1.8.3 allows remote attackers to
    cause a denial of service (application crash) or
    possibly have unspecified other impact via a malformed
    packet. (CVE-2012-5240)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f035c3e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.3.4.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.3.0.4.0", sru:"SRU 11.1.3.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
