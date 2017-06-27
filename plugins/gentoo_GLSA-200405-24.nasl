#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-24.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14510);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0433");
  script_xref(name:"GLSA", value:"200405-24");

  script_name(english:"GLSA-200405-24 : MPlayer, xine-lib: vulnerabilities in RTSP stream handling");
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
"The remote host is affected by the vulnerability described in GLSA-200405-24
(MPlayer, xine-lib: vulnerabilities in RTSP stream handling)

    Multiple vulnerabilities have been found and fixed in the RTSP handling
    code common to recent versions of these two packages. These vulnerabilities
    include several remotely exploitable buffer overflows.
  
Impact :

    A remote attacker, posing as a RTSP stream server, can execute arbitrary
    code with the rights of the user of the software playing the stream
    (MPlayer or any player using xine-lib). Another attacker may entice a user
    to use a maliciously crafted URL or playlist to achieve the same results.
  
Workaround :

    For MPlayer, there is no known workaround at this time. For xine-lib, you
    can delete the xineplug_inp_rtsp.so file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xinehq.de/index.php/security/XSA-2004-3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-24"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to non-vulnerable versions of MPlayer and
    xine-lib:
    # emerge sync
    # emerge -pv '>=media-video/mplayer-1.0_pre4'
    # emerge '>=media-video/mplayer-1.0_pre4'
    # emerge -pv '>=media-libs/xine-lib-1_rc4'
    # emerge '>=media-libs/xine-lib-1_rc4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xine-lib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
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

if (qpkg_check(package:"media-video/mplayer", unaffected:make_list("ge 1.0_pre4", "le 0.92-r1"), vulnerable:make_list("lt 1.0_pre4"))) flag++;
if (qpkg_check(package:"media-libs/xine-lib", unaffected:make_list("ge 1_rc4", "le 0.9.13-r3"), vulnerable:make_list("lt 1_rc4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MPlayer / xine-lib");
}
