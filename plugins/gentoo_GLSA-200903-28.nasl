#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200903-28.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35929);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");
  script_bugtraq_id(31920, 33827);
  script_osvdb_id(49374, 53314, 53315, 53316, 53317);
  script_xref(name:"GLSA", value:"200903-28");

  script_name(english:"GLSA-200903-28 : libpng: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200903-28
(libpng: Multiple vulnerabilities)

    Multiple vulnerabilities were discovered in libpng:
    A
    memory leak bug was reported in png_handle_tEXt(), a function that is
    used while reading PNG images (CVE-2008-6218).
    A memory
    overwrite bug was reported by Jon Foster in png_check_keyword(), caused
    by writing overlong keywords to a PNG file (CVE-2008-5907).
    A
    memory corruption issue, caused by an incorrect handling of an out of
    memory condition has been reported by Tavis Ormandy of the Google
    Security Team. That vulnerability affects direct uses of
    png_read_png(), pCAL chunk and 16-bit gamma table handling
    (CVE-2009-0040).
  
Impact :

    A remote attacker may execute arbitrary code with the privileges of the
    user opening a specially crafted PNG file by exploiting the erroneous
    out-of-memory handling. An attacker may also exploit the
    png_check_keyword() error to set arbitrary memory locations to 0, if
    the application allows overlong, user-controlled keywords when writing
    PNG files. The png_handle_tEXT() vulnerability may be exploited by an
    attacker to potentially consume all memory on a users system when a
    specially crafted PNG file is opened.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200903-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/libpng-1.2.35'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/libpng", unaffected:make_list("ge 1.2.35"), vulnerable:make_list("lt 1.2.35"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng");
}
