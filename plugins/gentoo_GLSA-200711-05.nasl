#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200711-05.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(27816);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5692", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695");
  script_osvdb_id(26869, 41110, 41355, 41356, 41357, 41358, 41359, 41581, 43604, 43760, 45516);
  script_xref(name:"GLSA", value:"200711-05");

  script_name(english:"GLSA-200711-05 : SiteBar: Multiple issues");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200711-05
(SiteBar: Multiple issues)

    Tim Brown discovered these multiple issues: the translation module does
    not properly sanitize the value to the 'dir' parameter (CVE-2007-5491,
    CVE-2007-5694); the translation module also does not sanitize the
    values of the 'edit' and 'value' parameters which it passes to eval()
    and include() (CVE-2007-5492, CVE-2007-5693); the log-in command does
    not validate the URL to redirect users to after logging in
    (CVE-2007-5695); SiteBar also contains several cross-site scripting
    vulnerabilities (CVE-2007-5692).
  
Impact :

    An authenticated attacker in the 'Translators' or 'Admins' group could
    execute arbitrary code, read arbitrary files and possibly change their
    permissions with the privileges of the user running the web server by
    passing a specially crafted parameter string to the 'translator.php'
    file. An unauthenticated attacker could entice a user to browse a
    specially crafted URL, allowing for the execution of script code in the
    context of the user's browser, for the theft of browser credentials or
    for a redirection to an arbitrary website after login.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200711-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SiteBar users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/sitebar-3.3.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(22, 59, 79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sitebar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"www-apps/sitebar", unaffected:make_list("ge 3.3.9"), vulnerable:make_list("lt 3.3.9"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SiteBar");
}
