#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200511-14.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20235);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/04 15:13:58 $");

  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_osvdb_id(20840, 20841, 20842);
  script_xref(name:"GLSA", value:"200511-14");

  script_name(english:"GLSA-200511-14 : GTK+ 2, GdkPixbuf: Multiple XPM decoding vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200511-14
(GTK+ 2, GdkPixbuf: Multiple XPM decoding vulnerabilities)

    iDEFENSE reported a possible heap overflow in the XPM loader
    (CVE-2005-3186). Upon further inspection, Ludwig Nussel discovered two
    additional issues in the XPM processing functions : an integer overflow
    (CVE-2005-2976) that affects only gdk-pixbuf, and an infinite loop
    (CVE-2005-2975).
  
Impact :

    Using a specially crafted XPM image an attacker could cause an
    affected application to enter an infinite loop or trigger the
    overflows, potentially allowing the execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=339&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd0fae5b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200511-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GTK+ 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose x11-libs/gtk+
    All GdkPixbuf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gdk-pixbuf-0.22.0-r5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gtk+");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/gdk-pixbuf", unaffected:make_list("ge 0.22.0-r5"), vulnerable:make_list("lt 0.22.0-r5"))) flag++;
if (qpkg_check(package:"x11-libs/gtk+", unaffected:make_list("ge 2.8.6-r1", "rge 2.6.10-r1", "lt 2.0"), vulnerable:make_list("lt 2.8.6-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GTK+ 2 / GdkPixbuf");
}
