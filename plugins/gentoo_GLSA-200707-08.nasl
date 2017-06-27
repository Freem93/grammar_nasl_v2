#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200707-08.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25790);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:56:54 $");

  script_cve_id("CVE-2007-3531");
  script_osvdb_id(38573);
  script_xref(name:"GLSA", value:"200707-08");

  script_name(english:"GLSA-200707-08 : NVClock: Insecure file usage");
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
"The remote host is affected by the vulnerability described in GLSA-200707-08
(NVClock: Insecure file usage)

    Tavis Ormandy of the Gentoo Linux Security Team discovered that NVClock
    makes usage of an insecure temporary file in the /tmp directory.
  
Impact :

    A local attacker could create a specially crafted temporary file in
    /tmp to execute arbitrary code with the privileges of the user running
    NVCLock.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200707-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All NVClock users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/nvclock-0.7-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nvclock");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/03");
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

if (qpkg_check(package:"media-video/nvclock", unaffected:make_list("ge 0.7-r2"), vulnerable:make_list("lt 0.7-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NVClock");
}
