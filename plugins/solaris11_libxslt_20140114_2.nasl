#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80695);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-1202", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");

  script_name(english:"Oracle Solaris Third-Party Patch Update : libxslt (multiple_vulnerabilities_in_libxslt)");
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

  - The xsltGenerateIdFunction function in functions.c in
    libxslt 1.1.26 and earlier, as used in Google Chrome
    before 10.0.648.127 and other products, allows remote
    attackers to obtain potentially sensitive information
    about heap memory addresses via an XML document
    containing a call to the XSLT generate-id XPath
    function. (CVE-2011-1202)

  - The XSL implementation in Google Chrome before
    20.0.1132.43 allows remote attackers to cause a denial
    of service (incorrect read operation) via unspecified
    vectors. (CVE-2012-2825)

  - libxslt 1.1.26 and earlier, as used in Google Chrome
    before 21.0.1180.89, does not properly manage memory,
    which might allow remote attackers to cause a denial of
    service (application crash) via a crafted XSLT
    expression that is not properly identified during XPath
    navigation, related to (1) the
    xsltCompileLocationPathPattern function in
    libxslt/pattern.c and (2) the xsltGenerateIdFunction
    function in libxslt/functions.c. (CVE-2012-2870)

  - libxml2 2.9.0-rc1 and earlier, as used in Google Chrome
    before 21.0.1180.89, does not properly support a cast of
    an unspecified variable during handling of XSL
    transforms, which allows remote attackers to cause a
    denial of service or possibly have unknown other impact
    via a crafted document, related to the _xmlNs data
    structure in include/libxml/tree.h. (CVE-2012-2871)

  - Double free vulnerability in libxslt, as used in Google
    Chrome before 22.0.1229.79, allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via vectors related to XSL transforms.
    (CVE-2012-2893)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_libxslt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e4e7824"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.4.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:libxslt");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^libxslt$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.4.0.5.0", sru:"SRU 4.5") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : libxslt\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "libxslt");
