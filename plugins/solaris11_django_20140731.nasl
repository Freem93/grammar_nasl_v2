#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80600);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474");

  script_name(english:"Oracle Solaris Third-Party Patch Update : django (multiple_vulnerabilities_in_django)");
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

  - The django.core.urlresolvers.reverse function in Django
    before 1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3,
    and 1.7.x before 1.7 beta 2 allows remote attackers to
    import and execute arbitrary Python modules by
    leveraging a view that constructs URLs using user input
    and a 'dotted Python path.' (CVE-2014-0472)

  - The caching framework in Django before 1.4.11, 1.5.x
    before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7
    beta 2 reuses a cached CSRF token for all anonymous
    users, which allows remote attackers to bypass CSRF
    protections by reading the CSRF cookie for anonymous
    users. (CVE-2014-0473)

  - The (1) FilePathField, (2) GenericIPAddressField, and
    (3) IPAddressField model field classes in Django before
    1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3, and
    1.7.x before 1.7 beta 2 do not properly perform type
    conversion, which allows remote attackers to have
    unspecified impact and vectors, related to 'MySQL
    typecasting.' (CVE-2014-0474)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_django
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cbcf288"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:django");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^django$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "django");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.0.0.0.0", sru:"11.2 SRU 0") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  error_extra = 'Affected package : django\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "django");
