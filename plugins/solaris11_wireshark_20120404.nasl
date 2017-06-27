#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80801);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-0041", "CVE-2012-0042", "CVE-2012-0043", "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-0068");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_denial_of_service_vulnerabilities2)");
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

  - The dissect_packet function in epan/packet.c in
    Wireshark 1.4.x before 1.4.11 and 1.6.x before 1.6.5
    allows remote attackers to cause a denial of service
    (application crash) via a long packet in a capture file,
    as demonstrated by an airopeek file. (CVE-2012-0041)

  - Wireshark 1.4.x before 1.4.11 and 1.6.x before 1.6.5
    does not properly perform certain string conversions,
    which allows remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a crafted packet, related to epan/to_str.c.
    (CVE-2012-0042)

  - Buffer overflow in the reassemble_message function in
    epan/dissectors/ packet-rlc.c in the RLC dissector in
    Wireshark 1.4.x before 1.4.11 and 1.6.x before 1.6.5
    allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a series of fragmented RLC packets. (CVE-2012-0043)

  - Wireshark 1.4.x before 1.4.11 and 1.6.x before 1.6.5
    allows remote attackers to cause a denial of service
    (application crash) via a long packet in a (1) Accellent
    5Views (aka .5vw) file, (2) I4B trace file, or (3)
    NETMON 2 capture file. (CVE-2012-0066)

  - wiretap/iptrace.c in Wireshark 1.4.x before 1.4.11 and
    1.6.x before 1.6.5 allows remote attackers to cause a
    denial of service (application crash) via a long packet
    in an AIX iptrace file. (CVE-2012-0067)

  - The lanalyzer_read function in wiretap/lanalyzer.c in
    Wireshark 1.4.x before 1.4.11 and 1.6.x before 1.6.5
    allows remote attackers to cause a denial of service
    (application crash) via a Novell catpure file containing
    a record that is too small. (CVE-2012-0068)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_vulnerabilities2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8e362ef"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 04.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.4.0.5.0", sru:"SRU 4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
