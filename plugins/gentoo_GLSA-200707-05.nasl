#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200707-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25680);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:56:54 $");

  script_cve_id("CVE-2007-3156");
  script_osvdb_id(36932);
  script_xref(name:"GLSA", value:"200707-05");

  script_name(english:"GLSA-200707-05 : Webmin, Usermin: XSS vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200707-05
(Webmin, Usermin: XSS vulnerabilities)

    The pam_login.cgi file does not properly sanitize user input before
    sending it back as output to the user.
  
Impact :

    An unauthenticated attacker could entice a user to browse a specially
    crafted URL, allowing for the execution of script code in the context
    of the user's browser and for the theft of browser credentials. This
    may permit the attacker to login to Webmin or Usermin with the user's
    permissions.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200707-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Webmin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot '>=app-admin/webmin-1.350'
    All Usermin users should update to the latest stable version:
    # emerge --sync
    # emerge --ask --verbose --oneshot '>=app-admin/usermin-1.280'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:usermin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-admin/usermin", unaffected:make_list("ge 1.280"), vulnerable:make_list("lt 1.280"))) flag++;
if (qpkg_check(package:"app-admin/webmin", unaffected:make_list("ge 1.350"), vulnerable:make_list("lt 1.350"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Webmin / Usermin");
}
