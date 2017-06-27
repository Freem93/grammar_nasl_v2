#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80614);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-5668", "CVE-2012-5669", "CVE-2012-5670");

  script_name(english:"Oracle Solaris Third-Party Patch Update : freetype (multiple_buffer_errors_vulnerabilities_in)");
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

  - FreeType before 2.4.11 allows context-dependent
    attackers to cause a denial of service (NULL pointer
    dereference and crash) via vectors related to BDF fonts
    and the improper handling of an 'allocation error' in
    the bdf_free_font function. (CVE-2012-5668)

  - The _bdf_parse_glyphs function in FreeType before 2.4.11
    allows context-dependent attackers to cause a denial of
    service (crash) and possibly execute arbitrary code via
    vectors related to BDF fonts and an incorrect
    calculation that triggers an out-of-bounds read.
    (CVE-2012-5669)

  - The _bdf_parse_glyphs function in FreeType before 2.4.11
    allows context-dependent attackers to cause a denial of
    service (out-of-bounds write and crash) via vectors
    related to BDF fonts and an ENCODING field with a
    negative value. (CVE-2012-5670)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_buffer_errors_vulnerabilities_in
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?002e043c"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.18.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:freetype");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^freetype-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.18.0.5.0", sru:"SRU 11.1.18.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : freetype\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "freetype");
