#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-23.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14774);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-1470");
  script_osvdb_id(10051);
  script_xref(name:"GLSA", value:"200409-23");

  script_name(english:"GLSA-200409-23 : SnipSnap: HTTP response splitting");
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
"The remote host is affected by the vulnerability described in GLSA-200409-23
(SnipSnap: HTTP response splitting)

    SnipSnap contains various HTTP response splitting vulnerabilities that
    could potentially compromise the sites data. Some of these attacks
    include web cache poisoning, cross-user defacement, hijacking pages
    with sensitive user information, and cross-site scripting. This
    vulnerability is due to the lack of illegal input checking in the
    software.
  
Impact :

    A malicious user could inject and execute arbitrary script code,
    potentially compromising the victim's data or browser.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://snipsnap.org/space/start/2004-09-14/1#SnipSnap_1.0b1_(uttoxeter)_released
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a47e4e1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All SnipSnap users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=dev-java/snipsnap-bin-1.0_beta1'
    # emerge '>=dev-java/snipsnap-bin-1.0beta1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:snipsnap-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-java/snipsnap-bin", unaffected:make_list("ge 1.0_beta1"), vulnerable:make_list("lt 1.0_beta1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "SnipSnap");
}
