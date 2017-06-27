#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200412-21.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16011);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_osvdb_id(12498, 12499, 12500, 12501);
  script_xref(name:"GLSA", value:"200412-21");

  script_name(english:"GLSA-200412-21 : MPlayer: Multiple overflows");
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
"The remote host is affected by the vulnerability described in GLSA-200412-21
(MPlayer: Multiple overflows)

    iDEFENSE, Ariel Berkman and the MPlayer development team found
    multiple vulnerabilities in MPlayer. These include potential heap
    overflows in Real RTSP and pnm streaming code, stack overflows in MMST
    streaming code and multiple buffer overflows in BMP demuxer and mp3lib
    code.
  
Impact :

    A remote attacker could craft a malicious file or design a
    malicious streaming server. Using MPlayer to view this file or connect
    to this server could trigger an overflow and execute
    attacker-controlled code.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://www.idefense.com/application/poi/display?id=168&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdbcba84"
  );
  # http://www.idefense.com/application/poi/display?id=167&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ef3169"
  );
  # http://www.idefense.com/application/poi/display?id=166&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7dac8f"
  );
  # http://tigger.uic.edu/~jlongs2/holes/mplayer.txt
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbfaeb90"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200412-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.0_pre5-r5'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
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

if (qpkg_check(package:"media-video/mplayer", unaffected:make_list("ge 1.0_pre5-r5"), vulnerable:make_list("le 1.0_pre5-r4"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:qpkg_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MPlayer");
}
