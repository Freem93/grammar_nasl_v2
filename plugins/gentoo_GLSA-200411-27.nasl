#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200411-27.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(15768);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/13 13:34:23 $");

  script_cve_id("CVE-2004-1030", "CVE-2004-1031", "CVE-2004-1032", "CVE-2004-1033");
  script_osvdb_id(11834, 11835, 11836, 11837);
  script_xref(name:"GLSA", value:"200411-27");

  script_name(english:"GLSA-200411-27 : Fcron: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200411-27
(Fcron: Multiple vulnerabilities)

    Due to design errors in the fcronsighup program, Fcron may allow a
    local user to bypass access restrictions (CAN-2004-1031), view the
    contents of root owned files (CAN-2004-1030), remove arbitrary files or
    create empty files (CAN-2004-1032), and send a SIGHUP to any process. A
    vulnerability also exists in fcrontab which may allow local users to
    view the contents of fcron.allow and fcron.deny (CAN-2004-1033).
  
Impact :

    A local attacker could exploit these vulnerabilities to perform a
    Denial of Service on the system running Fcron.
  
Workaround :

    Make sure the fcronsighup and fcrontab binaries are only
    executable by trusted users."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200411-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Fcron users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-process/fcron-2.0.2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:fcron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/15");
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

if (qpkg_check(package:"sys-process/fcron", unaffected:make_list("rge 2.0.2", "ge 2.9.5.1"), vulnerable:make_list("le 2.9.5"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Fcron");
}
