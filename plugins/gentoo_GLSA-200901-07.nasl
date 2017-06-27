#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200901-07.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(35355);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/11 20:08:44 $");

  script_cve_id("CVE-2008-3162", "CVE-2008-3827", "CVE-2008-5616");
  script_osvdb_id(46842, 48662, 50838);
  script_xref(name:"GLSA", value:"200901-07");

  script_name(english:"GLSA-200901-07 : MPlayer: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200901-07
(MPlayer: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in MPlayer:
    A
    stack-based buffer overflow was found in the str_read_packet() function
    in libavformat/psxstr.c when processing crafted STR files that
    interleave audio and video sectors (CVE-2008-3162).
    Felipe
    Andres Manzano reported multiple integer underflows in the
    demux_real_fill_buffer() function in demux_real.c when processing
    crafted Real Media files that cause the stream_read() function to read
    or write arbitrary memory (CVE-2008-3827).
    Tobias Klein
    reported a stack-based buffer overflow in the demux_open_vqf() function
    in libmpdemux/demux_vqf.c when processing malformed TwinVQ files
    (CVE-2008-5616).
  
Impact :

    A remote attacker could entice a user to open a specially crafted STR,
    Real Media, or TwinVQ file to execute arbitrary code or cause a Denial of
    Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200901-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.0_rc2_p28058-r1 '"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/13");
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

if (qpkg_check(package:"media-video/mplayer", unaffected:make_list("ge 1.0_rc2_p28058-r1 "), vulnerable:make_list("lt 1.0_rc2_p28058-r1 "))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MPlayer");
}
