#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200707-12.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(25808);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/13 13:56:54 $");

  script_cve_id("CVE-2007-3316");
  script_osvdb_id(37379, 37380, 37381, 37382);
  script_xref(name:"GLSA", value:"200707-12");

  script_name(english:"GLSA-200707-12 : VLC media player: Format string vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200707-12
(VLC media player: Format string vulnerabilities)

    David Thiel from iSEC Partners Inc. discovered format string errors in
    various plugins when parsing data. The affected plugins include Vorbis,
    Theora, CDDA and SAP.
  
Impact :

    A remote attacker could entice a user to open a specially crafted media
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user running VLC media player.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200707-12"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All VLC media player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=media-video/vlc-0.8.6c'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:vlc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/vlc", unaffected:make_list("ge 0.8.6c"), vulnerable:make_list("lt 0.8.6c"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "VLC media player");
}
