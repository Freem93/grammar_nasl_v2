#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200803-13.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(31439);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2007-6684", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0984");
  script_osvdb_id(42193, 42194, 42204, 42205, 42206, 42207, 42208, 43002);
  script_xref(name:"GLSA", value:"200803-13");

  script_name(english:"GLSA-200803-13 : VLC: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200803-13
(VLC: Multiple vulnerabilities)

    Multiple vulnerabilities were found in VLC:
    Michal Luczaj
    and Luigi Auriemma reported that VLC contains boundary errors when
    handling subtitles in the ParseMicroDvd(), ParseSSA(), and
    ParseVplayer() functions in the modules/demux/subtitle.c file, allowing
    for a stack-based buffer overflow (CVE-2007-6681).
    The web
    interface listening on port 8080/tcp contains a format string error in
    the httpd_FileCallBack() function in the network/httpd.c file
    (CVE-2007-6682).
    The browser plugin possibly contains an
    argument injection vulnerability (CVE-2007-6683).
    The RSTP
    module triggers a NULL pointer dereference when processing a request
    without a 'Transport' parameter (CVE-2007-6684).
    Luigi
    Auriemma and Remi Denis-Courmont found a boundary error in the
    modules/access/rtsp/real_sdpplin.c file when processing SDP data for
    RTSP sessions (CVE-2008-0295) and a vulnerability in the
    libaccess_realrtsp plugin (CVE-2008-0296), possibly resulting in a
    heap-based buffer overflow.
    Felipe Manzano and Anibal Sacco
    (Core Security Technologies) discovered an arbitrary memory overwrite
    vulnerability in VLC's MPEG-4 file format parser (CVE-2008-0984).
  
Impact :

    A remote attacker could send a long subtitle in a file that a user is
    enticed to open, a specially crafted MP4 input file, long SDP data, or
    a specially crafted HTTP request with a 'Connection' header value
    containing format specifiers, possibly resulting in the remote
    execution of arbitrary code. Also, a Denial of Service could be caused
    and arbitrary files could be overwritten via the 'demuxdump-file'
    option in a filename in a playlist or via an EXTVLCOPT statement in an
    MP3 file.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200803-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/vlc-0.8.6e'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");
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

if (qpkg_check(package:"media-video/vlc", unaffected:make_list("ge 0.8.6e"), vulnerable:make_list("lt 0.8.6e"))) flag++;

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
