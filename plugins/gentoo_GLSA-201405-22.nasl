#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201405-22.
#
# The advisory text is Copyright (C) 2001-2017 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(74064);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/19 13:27:08 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-0271", "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(57951, 57952, 57954, 65188, 65192, 65195, 65243, 65492);
  script_osvdb_id(90231, 90232, 90233, 90234, 102614, 102615, 102616, 102617, 102618, 102619, 102620, 102621, 102622, 102623, 102625, 102626, 102627, 102628, 102629);
  script_xref(name:"GLSA", value:"201405-22");

  script_name(english:"GLSA-201405-22 : Pidgin: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201405-22
(Pidgin: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Pidgin. Please review
      the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the Pidgin process, cause a Denial of Service condition,
      overwrite files, or spoof traffic.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201405-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Pidgin users on HPPA or users of GNOME 3.8 and later on AMD64 or X86
      should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-im/pidgin-2.10.9-r1'
    All Pidgin users on ALPHA, PPC, PPC64, SPARC, and users of GNOME before
      3.8 on AMD64 and X86 should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=net-im/pidgin-2.10.9'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-im/pidgin", unaffected:make_list("ge 2.10.9", "rge 2.10.9-r1"), vulnerable:make_list("lt 2.10.9"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Pidgin");
}
