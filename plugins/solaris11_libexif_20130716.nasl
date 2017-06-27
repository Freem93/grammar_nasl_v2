#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80668);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841", "CVE-2012-2845");

  script_name(english:"Oracle Solaris Third-Party Patch Update : libexif (multiple_vulnerabilities_in_libexif1)");
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

  - The exif_entry_get_value function in exif-entry.c in the
    EXIF Tag Parsing Library (aka libexif) before 0.6.21
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from process memory via crafted EXIF tags in
    an image. (CVE-2012-2812)

  - The exif_convert_utf16_to_utf8 function in exif-entry.c
    in the EXIF Tag Parsing Library (aka libexif) before
    0.6.21 allows remote attackers to cause a denial of
    service (out-of-bounds read) or possibly obtain
    sensitive information from process memory via crafted
    EXIF tags in an image. (CVE-2012-2813)

  - Buffer overflow in the exif_entry_format_value function
    in exif-entry.c in the EXIF Tag Parsing Library (aka
    libexif) 0.6.20 allows remote attackers to cause a
    denial of service or possibly execute arbitrary code via
    crafted EXIF tags in an image. (CVE-2012-2814)

  - The exif_data_load_data function in exif-data.c in the
    EXIF Tag Parsing Library (aka libexif) before 0.6.21
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from process memory via crafted EXIF tags in
    an image. (CVE-2012-2836)

  - The mnote_olympus_entry_get_value function in
    olympus/mnote-olympus-entry.c in the EXIF Tag Parsing
    Library (aka libexif) before 0.6.21 allows remote
    attackers to cause a denial of service (divide-by-zero
    error) via an image with crafted EXIF tags that are not
    properly handled during the formatting of EXIF maker
    note tags. (CVE-2012-2837)

  - Off-by-one error in the exif_convert_utf16_to_utf8
    function in exif-entry.c in the EXIF Tag Parsing Library
    (aka libexif) before 0.6.21 allows remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via crafted EXIF tags in an image. (CVE-2012-2840)

  - Integer underflow in the exif_entry_get_value function
    in exif-entry.c in the EXIF Tag Parsing Library (aka
    libexif) 0.6.20 might allow remote attackers to execute
    arbitrary code via vectors involving a crafted
    buffer-size parameter during the formatting of an EXIF
    tag, leading to a heap-based buffer overflow.
    (CVE-2012-2841)

  - Integer overflow in the jpeg_data_load_data function in
    jpeg-data.c in libjpeg in exif 0.6.20 allows remote
    attackers to cause a denial of service (buffer over-read
    and application crash) or obtain potentially sensitive
    information via a crafted JPEG file. (CVE-2012-2845)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_libexif1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa73227e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 12.4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:libexif");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/16");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^libexif$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "libexif");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.12.0.4.0", sru:"SRU 12.4") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : libexif\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "libexif");
