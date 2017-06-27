#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201705-10.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(100263);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/18 13:19:45 $");

  script_cve_id("CVE-2016-10198", "CVE-2016-10199", "CVE-2016-9445", "CVE-2016-9446", "CVE-2016-9447", "CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807", "CVE-2016-9808", "CVE-2016-9809", "CVE-2016-9810", "CVE-2016-9811", "CVE-2016-9812", "CVE-2016-9813", "CVE-2017-5837", "CVE-2017-5838", "CVE-2017-5839", "CVE-2017-5840", "CVE-2017-5841", "CVE-2017-5842", "CVE-2017-5843", "CVE-2017-5844", "CVE-2017-5845", "CVE-2017-5846", "CVE-2017-5847", "CVE-2017-5848");
  script_xref(name:"GLSA", value:"201705-10");

  script_name(english:"GLSA-201705-10 : GStreamer plug-ins: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-201705-10
(GStreamer plug-ins: User-assisted execution of arbitrary code)

    Multiple vulnerabilities have been discovered in various GStreamer
      plug-ins. Please review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could entice a user or automated system using a
      GStreamer plug-in to process a specially crafted file, resulting in the
      execution of arbitrary code or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201705-10"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All gst-plugins-bad users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-libs/gst-plugins-bad-1.10.3:1.0'
    All gst-plugins-good users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-libs/gst-plugins-good-1.10.3:1.0'
    All gst-plugins-base users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-libs/gst-plugins-base-1.10.3:1.0'
    All gst-plugins-ugly users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=media-libs/gst-plugins-ugly-1.10.3:1.0'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-bad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-ugly");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-libs/gst-plugins-base", unaffected:make_list("ge 1.10.3"), vulnerable:make_list("lt 1.10.3"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-ugly", unaffected:make_list("ge 1.10.3"), vulnerable:make_list("lt 1.10.3"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-bad", unaffected:make_list("ge 1.10.3"), vulnerable:make_list("lt 1.10.3"))) flag++;
if (qpkg_check(package:"media-libs/gst-plugins-good", unaffected:make_list("ge 1.10.3"), vulnerable:make_list("lt 1.10.3"))) flag++;

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
