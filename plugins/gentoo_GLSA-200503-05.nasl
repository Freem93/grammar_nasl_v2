#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200503-05.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(17261);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:58 $");

  script_cve_id("CVE-2001-0775", "CVE-2005-0638", "CVE-2005-0639");
  script_osvdb_id(13969, 14357, 14365, 14366, 14403);
  script_xref(name:"GLSA", value:"200503-05");

  script_name(english:"GLSA-200503-05 : xli, xloadimage: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200503-05
(xli, xloadimage: Multiple vulnerabilities)

    Tavis Ormandy of the Gentoo Linux Security Audit Team has reported that
    xli and xloadimage contain a flaw in the handling of compressed images,
    where shell meta-characters are not adequately escaped. Rob Holland of
    the Gentoo Linux Security Audit Team has reported that an xloadimage
    vulnerability in the handling of Faces Project images discovered by
    zen-parse in 2001 remained unpatched in xli. Additionally, it has been
    reported that insufficient validation of image properties in xli could
    potentially result in buffer management errors.
  
Impact :

    Successful exploitation would permit a remote attacker to execute
    arbitrary shell commands, or arbitrary code with the privileges of the
    xloadimage or xli user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200503-05"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All xli users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-gfx/xli-1.17.0-r1'
    All xloadimage users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-gfx/xloadimage-4.1-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xloadimage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/10");
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

if (qpkg_check(package:"media-gfx/xloadimage", unaffected:make_list("ge 4.1-r2"), vulnerable:make_list("lt 4.1-r2"))) flag++;
if (qpkg_check(package:"media-gfx/xli", unaffected:make_list("ge 1.17.0-r1"), vulnerable:make_list("lt 1.17.0-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xli / xloadimage");
}
