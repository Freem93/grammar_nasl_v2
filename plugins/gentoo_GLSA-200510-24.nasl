#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200510-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20117);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:49:33 $");

  script_cve_id("CVE-2005-3335", "CVE-2005-3336", "CVE-2005-3337", "CVE-2005-3338", "CVE-2005-3339");
  script_osvdb_id(18900, 18901, 18902, 20319, 20324);
  script_xref(name:"GLSA", value:"200510-24");

  script_name(english:"GLSA-200510-24 : Mantis: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200510-24
(Mantis: Multiple vulnerabilities)

    Mantis contains several vulnerabilities, including:
    a remote file inclusion vulnerability
    a SQL injection vulnerability
    multiple cross site scripting vulnerabilities
    multiple information disclosure vulnerabilities
  
Impact :

    An attacker could exploit the remote file inclusion vulnerability to
    execute arbitrary script code, and the SQL injection vulnerability to
    access or modify sensitive information from the Mantis database.
    Furthermore the cross-site scripting issues give an attacker the
    ability to inject and execute malicious script code or to steal
    cookie-based authentication credentials, potentially compromising the
    victim's browser. An attacker could exploit other vulnerabilities to
    disclose information.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.mantisbt.org/changelog.php
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mantisbt.org/bugs/changelog_page.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200510-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mantis users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-apps/mantisbt-0.19.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mantisbt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-apps/mantisbt", unaffected:make_list("ge 0.19.3"), vulnerable:make_list("lt 0.19.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mantis");
}
