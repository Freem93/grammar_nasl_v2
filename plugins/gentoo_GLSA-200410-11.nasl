#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200410-11.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15472);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-0803");
  script_osvdb_id(10750);
  script_xref(name:"GLSA", value:"200410-11");

  script_name(english:"GLSA-200410-11 : tiff: Buffer overflows in image decoding");
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
"The remote host is affected by the vulnerability described in GLSA-200410-11
(tiff: Buffer overflows in image decoding)

    Chris Evans found heap-based overflows in RLE decoding routines in
    tif_next.c, tif_thunder.c and potentially tif_luv.c.
  
Impact :

    A remote attacker could entice a user to view a carefully crafted TIFF
    image file, which would potentially lead to execution of arbitrary code
    with the rights of the user viewing the image. This affects any program
    that makes use of the tiff library, including GNOME and KDE web browsers or
    mail readers.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200410-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All tiff library users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=media-libs/tiff-3.6.1-r2'
    # emerge '>=media-libs/tiff-3.6.1-r2'
    xv makes use of the tiff library and needs to be recompiled to receive the
    new patched version of the library. All xv users should also upgrade to the
    latest version:
    # emerge sync
    # emerge -pv '>=media-gfx/xv-3.10a-r8'
    # emerge '>=media-gfx/xv-3.10a-r8'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/14");
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

if (qpkg_check(package:"media-gfx/xv", unaffected:make_list("ge 3.10a-r8"), vulnerable:make_list("le 3.10a-r7"))) flag++;
if (qpkg_check(package:"media-libs/tiff", unaffected:make_list("ge 3.6.1-r2"), vulnerable:make_list("lt 3.6.1-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
