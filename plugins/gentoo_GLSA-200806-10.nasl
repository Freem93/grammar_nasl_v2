#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200806-10.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33246);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 14:04:26 $");

  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_osvdb_id(46175, 46176, 46177, 46178);
  script_xref(name:"GLSA", value:"200806-10");

  script_name(english:"GLSA-200806-10 : FreeType: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200806-10
(FreeType: User-assisted execution of arbitrary code)

    Regenrecht reported multiple vulnerabilities in FreeType via iDefense:
    An integer overflow when parsing values in the Private dictionary table
    in a PFB file, leading to a heap-based buffer overflow
    (CVE-2008-1806).
    An invalid free() call related to parsing an invalid 'number of axes'
    field in a PFB file (CVE-2008-1807).
    Multiple off-by-one errors when parsing PBF and TTF files, leading to
    heap-based buffer overflows (CVE-2008-1808).
  
Impact :

    A remote attacker could entice a user to open a specially crafted TTF
    or PBF file, possibly resulting in the execution of arbitrary code with
    the privileges of the user running an application linked against
    FreeType (such as the X.org X server, running as root).
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200806-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FreeType users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/freetype-2.3.6'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/freetype", unaffected:make_list("ge 2.3.6", "rge 1.4_pre20080316-r1"), vulnerable:make_list("lt 2.3.6"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FreeType");
}
