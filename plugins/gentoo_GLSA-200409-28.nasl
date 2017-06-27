#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-28.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14791);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_osvdb_id(9996, 9997, 9998, 9999);
  script_xref(name:"GLSA", value:"200409-28");

  script_name(english:"GLSA-200409-28 : GTK+ 2, gdk-pixbuf: Multiple image decoding vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200409-28
(GTK+ 2, gdk-pixbuf: Multiple image decoding vulnerabilities)

    A vulnerability has been discovered in the BMP image preprocessor
    (CAN-2004-0753). Furthermore, Chris Evans found a possible integer overflow
    in the pixbuf_create_from_xpm() function, resulting in a heap overflow
    (CAN-2004-0782). He also found a potential stack-based buffer overflow in
    the xpm_extract_color() function (CAN-2004-0783). A possible integer
    overflow has also been found in the ICO decoder.
  
Impact :

    With a specially crafted BMP image an attacker could cause an affected
    application to enter an infinite loop when that image is being processed.
    Also, by making use of specially crafted XPM or ICO images an attacker
    could trigger the overflows, which potentially allows the execution of
    arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.gnome.org/show_bug.cgi?id=150601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GTK+ 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=x11-libs/gtk+-2.4.9-r1'
    # emerge '>=x11-libs/gtk+-2.4.9-r1'
    All GdkPixbuf users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=media-libs/gdk-pixbuf-0.22.0-r3'
    # emerge '>=media-libs/gdk-pixbuf-0.22.0-r3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gtk+");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");
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

if (qpkg_check(package:"media-libs/gdk-pixbuf", unaffected:make_list("ge 0.22.0-r3"), vulnerable:make_list("lt 0.22.0-r3"))) flag++;
if (qpkg_check(package:"x11-libs/gtk+", unaffected:make_list("ge 2.4.9-r1", "lt 2.0.0"), vulnerable:make_list("lt 2.4.9-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GTK+ 2 / gdk-pixbuf");
}
