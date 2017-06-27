#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200504-21.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(18121);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/02/23 16:41:17 $");

  script_cve_id("CVE-2005-0755");
  script_osvdb_id(15710, 15742);
  script_xref(name:"GLSA", value:"200504-21");

  script_name(english:"GLSA-200504-21 : RealPlayer, Helix Player: Buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200504-21
(RealPlayer, Helix Player: Buffer overflow vulnerability)

    Piotr Bania has discovered a buffer overflow vulnerability in
    RealPlayer and Helix Player when processing malicious RAM files.
  
Impact :

    By enticing a user to play a specially crafted RAM file an
    attacker could execute arbitrary code with the permissions of the user
    running the application.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://service.real.com/help/faq/security/050419_player/EN/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200504-21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/realplayer-10.0.4'
    All Helix Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/helixplayer-1.0.4'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:helixplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:realplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/helixplayer", unaffected:make_list("ge 1.0.4"), vulnerable:make_list("lt 1.0.4"))) flag++;
if (qpkg_check(package:"media-video/realplayer", unaffected:make_list("ge 10.0.4"), vulnerable:make_list("lt 10.0.4"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "RealPlayer / Helix Player");
}
