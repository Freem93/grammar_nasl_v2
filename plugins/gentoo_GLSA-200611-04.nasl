#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200611-04.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(23669);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:56:52 $");

  script_cve_id("CVE-2006-5453", "CVE-2006-5454", "CVE-2006-5455");
  script_osvdb_id(29545, 29546, 29547, 29548);
  script_xref(name:"GLSA", value:"200611-04");

  script_name(english:"GLSA-200611-04 : Bugzilla: Multiple Vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200611-04
(Bugzilla: Multiple Vulnerabilities)

    The vulnerabilities identified in Bugzilla are as follows:
    Frederic Buclin and Gervase Markham discovered that input passed to
    various fields throughout Bugzilla were not properly sanitized before
    being sent back to users (CVE-2006-5453).
    Frederic Buclin and Josh 'timeless' Soref discovered a bug when
    viewing attachments in diff mode that allows users not of the
    'insidergroup' to read attachment descriptions. Additionally, it was
    discovered that the 'deadline' field is visible to users who do not
    belong to the 'timetrackinggroup' when bugs are exported to XML
    (CVE-2006-5454).
    Gavin Shelley reported that Bugzilla allows certain operations to
    be performed via HTTP GET and HTTP POST requests without verifying
    those requests properly (CVE-2006-5455).
    Max Kanat-Alexander discovered that input passed to
    showdependencygraph.cgi is not properly sanitized before being returned
    to users (CVE-2006-5453).
  
Impact :

    An attacker could inject scripts into the content loaded by a user's
    browser in order to have those scripts executed in a user's browser in
    the context of the site currently being viewed. This could include
    gaining access to privileged session information for the site being
    viewed. Additionally, a user could forge an HTTP request in order to
    create, modify, or delete bugs within a Bugzilla instance. Lastly, an
    unauthorized user could view sensitive information about bugs or bug
    attachments.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200611-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Bugzilla users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/bugzilla-2.18.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/bugzilla", unaffected:make_list("ge 2.18.6"), vulnerable:make_list("lt 2.18.6"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Bugzilla");
}
