#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200903-33.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35969);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-3162", "CVE-2008-4866", "CVE-2008-4867", "CVE-2008-4868", "CVE-2008-4869", "CVE-2009-0385");
  script_bugtraq_id(33502);
  script_osvdb_id(46842, 50254, 50259, 50260, 50261, 51643);
  script_xref(name:"GLSA", value:"200903-33");

  script_name(english:"GLSA-200903-33 : FFmpeg: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200903-33
(FFmpeg: Multiple vulnerabilities)

    Multiple vulnerabilities were found in FFmpeg:
    astrange
    reported a stack-based buffer overflow in the str_read_packet() in
    libavformat/psxstr.c when processing .str files (CVE-2008-3162).
    Multiple buffer overflows in libavformat/utils.c
    (CVE-2008-4866).
    A buffer overflow in libavcodec/dca.c
    (CVE-2008-4867).
    An unspecified vulnerability in the
    avcodec_close() function in libavcodec/utils.c (CVE-2008-4868).
    Unspecified memory leaks (CVE-2008-4869).
    Tobias Klein
    repoerted a NULL pointer dereference due to an integer signedness error
    in the fourxm_read_header() function in libavformat/4xm.c
    (CVE-2009-0385).
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
    file, possibly leading to the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200903-33"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All FFmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/ffmpeg-0.4.9_p20090201'
    All gst-plugins-ffmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-plugins/gst-plugins-ffmpeg-0.10.5'
    All Mplayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.0_rc2_p28450'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gst-plugins-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/20");
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

if (qpkg_check(package:"media-plugins/gst-plugins-ffmpeg", unaffected:make_list("ge 0.10.5"), vulnerable:make_list("lt 0.10.5"))) flag++;
if (qpkg_check(package:"media-video/mplayer", unaffected:make_list("ge 1.0_rc2_p28450"), vulnerable:make_list("lt 1.0_rc2_p28450"))) flag++;
if (qpkg_check(package:"media-video/ffmpeg", unaffected:make_list("ge 0.4.9_p20090201"), vulnerable:make_list("lt 0.4.9_p20090201"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "FFmpeg");
}
