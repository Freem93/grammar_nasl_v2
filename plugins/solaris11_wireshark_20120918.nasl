#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80803);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-2392", "CVE-2012-2393", "CVE-2012-2394", "CVE-2012-4048", "CVE-2012-4049");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark1)");
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

  - Wireshark 1.4.x before 1.4.13 and 1.6.x before 1.6.8
    allows remote attackers to cause a denial of service
    (infinite loop) via vectors related to the (1) ANSI MAP,
    (2) ASF, (3) IEEE 802.11, (4) IEEE 802.3, and (5) LTP
    dissectors. (CVE-2012-2392)

  - epan/dissectors/packet-diameter.c in the DIAMETER
    dissector in Wireshark 1.4.x before 1.4.13 and 1.6.x
    before 1.6.8 does not properly construct certain array
    data structures, which allows remote attackers to cause
    a denial of service (application crash) via a crafted
    packet that triggers incorrect memory allocation.
    (CVE-2012-2393)

  - Wireshark 1.4.x before 1.4.13 and 1.6.x before 1.6.8 on
    the SPARC and Itanium platforms does not properly
    perform data alignment for a certain structure member,
    which allows remote attackers to cause a denial of
    service (application crash) via a (1) ICMP or (2) ICMPv6
    Echo Request packet. (CVE-2012-2394)

  - The PPP dissector in Wireshark 1.4.x before 1.4.14,
    1.6.x before 1.6.9, and 1.8.x before 1.8.1 allows remote
    attackers to cause a denial of service (invalid pointer
    dereference and application crash) via a crafted packet,
    as demonstrated by a usbmon dump. (CVE-2012-4048)

  - epan/dissectors/packet-nfs.c in the NFS dissector in
    Wireshark 1.4.x before 1.4.14, 1.6.x before 1.6.9, and
    1.8.x before 1.8.1 allows remote attackers to cause a
    denial of service (loop and CPU consumption) via a
    crafted packet. (CVE-2012-4049)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fcb839f0"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_wireshark2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d357ff67"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 11.4.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/18");
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

if (solaris_check_release(release:"0.5.11-0.175.0.11.0.4.1", sru:"SRU 11.4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_note(port:0, extra:error_extra);
  else security_note(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
