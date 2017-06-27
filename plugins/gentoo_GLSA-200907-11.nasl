#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200907-11.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(39782);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397", "CVE-2009-0586", "CVE-2009-1932");
  script_bugtraq_id(33405, 34100);
  script_osvdb_id(52775, 53550, 54827);
  script_xref(name:"GLSA", value:"200907-11");

  script_name(english:"GLSA-200907-11 : GStreamer plug-ins: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200907-11
(GStreamer plug-ins: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been reported in several GStreamer
    plug-ins:
    Tobias Klein reported two heap-based buffer overflows and an array
    index error in the qtdemux_parse_samples() function in gst-plugins-good
    when processing a QuickTime media .mov file (CVE-2009-0386,
    CVE-2009-0387, CVE-2009-0397).
    Thomas Hoger of the Red Hat Security Response Team reported an integer
    overflow that can lead to a heap-based buffer overflow in the
    gst_vorbis_tag_add_coverart() function in gst-plugins-base when
    processing COVERART tags (CVE-2009-0586).
    Tielei Wang of ICST-ERCIS, Peking University reported multiple integer
    overflows leading to buffer overflows in gst-plugins-libpng when
    processing a PNG file (CVE-2009-1932).
  
Impact :

    A remote attacker could entice a user or automated system using a
    GStreamer plug-in to process a specially crafted file, resulting in the
    execution of arbitrary code or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200907-11"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All gst-plugins-good users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-good-0.10.14'
    All gst-plugins-base users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-libs/gst-plugins-base-0.10.22'
    All gst-plugins-libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-plugins/gst-plugins-libpng-0.10.14-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/13");
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

if (qpkg_check(package:"media-plugins/gst-plugins-libpng", unaffected:make_list("ge 0.10.14-r1"), vulnerable:make_list("lt 0.10.14-r1"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-base", unaffected:make_list("ge 0.10.22"), vulnerable:make_list("lt 0.10.22"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-good", unaffected:make_list("ge 0.10.14"), vulnerable:make_list("lt 0.10.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GStreamer plug-ins");
}
