#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201401-28.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(72130);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/13 14:27:07 $");

  script_cve_id("CVE-2010-4005");
  script_bugtraq_id(44750);
  script_osvdb_id(69108);
  script_xref(name:"GLSA", value:"201401-28");

  script_name(english:"GLSA-201401-28 : Tomboy: Privilege escalation");
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
"The remote host is affected by the vulnerability described in GLSA-201401-28
(Tomboy: Privilege escalation)

    Tomboy places a zero-length directory name in the LD_LIBRARY_PATH, which
      might result in the current working directory (.) to be included when
      searching for dynamically linked libraries.
    NOTE: This vulnerability exists due to an incomplete fix for
      CVE-2005-4790 (GLSA 200711-12).
  
Impact :

    A local attacker could gain escalated privileges via a specially crafted
      shared library.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.gentoo.org/security/en/glsa/glsa-200711-12.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201401-28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Tomboy users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=app-misc/tomboy-1.4.2-r1'
    NOTE: This is a legacy GLSA. Updates for all affected architectures are
      available since March 02, 2011. It is likely that your system is already
      no longer affected by this issue."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomboy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"app-misc/tomboy", unaffected:make_list("ge 1.4.2-r1"), vulnerable:make_list("lt 1.4.2-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Tomboy");
}
