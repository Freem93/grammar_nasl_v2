#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200804-25.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32045);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-6681", "CVE-2008-0073", "CVE-2008-1489", "CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881");
  script_osvdb_id(42207, 43436, 43702, 44461, 44578, 44716, 44717, 44718);
  script_xref(name:"GLSA", value:"200804-25");

  script_name(english:"GLSA-200804-25 : VLC: User-assisted execution of arbitrary code");
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
"The remote host is affected by the vulnerability described in GLSA-200804-25
(VLC: User-assisted execution of arbitrary code)

    Multiple vulnerabilities were found in VLC:
    Luigi Auriemma discovered that the stack-based buffer overflow when
    reading subtitles, which has been reported as CVE-2007-6681 in GLSA
    200803-13, was not properly fixed (CVE-2008-1881).
    Alin Rad Pop of Secunia reported an array indexing vulnerability in the
    sdpplin_parse() function when processing streams from RTSP servers in
    Xine code, which is also used in VLC (CVE-2008-0073).
    Drew Yao and Nico Golde reported an integer overflow in the
    MP4_ReadBox_rdrf() function in the file libmp4.c leading to a
    heap-based buffer overflow when reading MP4 files (CVE-2008-1489).
    Drew Yao also reported integer overflows in the MP4 demuxer,
    the Real demuxer and in the Cinepak codec, which might lead to buffer
    overflows (CVE-2008-1768).
    Drew Yao finally discovered and a
    boundary error in Cinepak, which might lead to memory corruption
    (CVE-2008-1769).
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
    file or stream, possibly resulting in the remote execution of arbitrary
    code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200803-13.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200804-25"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/vlc-0.8.6f'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/vlc", unaffected:make_list("ge 0.8.6f"), vulnerable:make_list("lt 0.8.6f"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VLC");
}
