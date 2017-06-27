#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200602-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(20864);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:49:34 $");

  script_cve_id("CVE-2005-4048");
  script_osvdb_id(21458);
  script_xref(name:"GLSA", value:"200602-01");

  script_name(english:"GLSA-200602-01 : GStreamer FFmpeg plugin: Heap-based buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200602-01
(GStreamer FFmpeg plugin: Heap-based buffer overflow)

    The GStreamer FFmpeg plugin contains derived code from the FFmpeg
    library, which is vulnerable to a heap overflow in the
    'avcodec_default_get_buffer()' function discovered by Simon Kilvington
    (see GLSA 200601-06).
  
Impact :

    A remote attacker could entice a user to run an application using
    the GStreamer FFmpeg plugin on a maliciously crafted PIX_FMT_PAL8
    format image file (like PNG images), possibly leading to the execution
    of arbitrary code with the permissions of the user running the
    application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200601-06.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200602-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All GStreamer FFmpeg plugin users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-plugins/gst-plugins-ffmpeg-0.8.7-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-plugins/gst-plugins-ffmpeg", unaffected:make_list("ge 0.8.7-r1"), vulnerable:make_list("lt 0.8.7-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GStreamer FFmpeg plugin");
}
