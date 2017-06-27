#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201310-13.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70648);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/13 14:27:07 $");

  script_cve_id("CVE-2007-6718", "CVE-2008-4610", "CVE-2010-2062", "CVE-2010-3429", "CVE-2011-3625");
  script_bugtraq_id(34136, 43546);
  script_osvdb_id(45940, 49423, 49424, 50079, 50080, 50081, 50082, 50083, 50084, 50085, 50086, 56605, 58503, 58504, 58505, 58506, 58507, 58508, 58509, 58510, 62327, 62328, 68269, 70650, 70651, 72577, 72579, 74604, 74926, 76802, 76803, 77033, 77035, 77289, 77290, 77291, 78090, 78634, 78635, 78636, 78637, 78638, 78639, 78640, 78641, 78642, 78643, 78644, 78645, 78646, 78647, 78648, 82128, 85267, 85268, 85269, 85270, 85271, 85272, 85273, 85274, 85275, 85276, 85277, 85278, 85279, 85280, 85281, 85282, 85283, 85284, 85285, 85286, 85287, 85288, 85289, 85290, 85291, 85292, 85293, 85294, 85295, 85300, 94161, 94162, 94163, 94164, 94165, 94166, 94527, 94528, 94529, 94530, 94531, 94532, 94654, 94666);
  script_xref(name:"GLSA", value:"201310-13");

  script_name(english:"GLSA-201310-13 : MPlayer: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201310-13
(MPlayer: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in MPlayer and the bundled
      FFmpeg. Please review the CVE identifiers and FFmpeg GLSA referenced
      below for details.
  
Impact :

    A remote attacker could entice a user to open a crafted media file to
      execute arbitrary code or cause a Denial of Service.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.gentoo.org/glsa/glsa-201310-12.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201310-13"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All MPlayer users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=media-video/mplayer-1.1-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MPlayer SAMI Subtitle File Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"media-video/mplayer", unaffected:make_list("ge 1.1-r1"), vulnerable:make_list("lt 1.1-r1"))) flag++;

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
