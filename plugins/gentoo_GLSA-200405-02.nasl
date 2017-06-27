#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-02.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14488);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:21 $");

  script_cve_id("CVE-2004-0234", "CVE-2004-0235");
  script_xref(name:"GLSA", value:"200405-02");

  script_name(english:"GLSA-200405-02 : Multiple vulnerabilities in LHa");
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
"The remote host is affected by the vulnerability described in GLSA-200405-02
(Multiple vulnerabilities in LHa)

    Ulf Harnhammar found two stack overflows and two directory traversal
    vulnerabilities in LHa version 1.14 and 1.17. A stack overflow occurs when
    testing or extracting archives containing long file or directory names.
    Furthermore, LHa doesn't contain sufficient protection against relative or
    absolute archive paths.
  
Impact :

    The stack overflows can be exploited to execute arbitrary code with the
    rights of the user testing or extracting the archive. The directory
    traversal vulnerabilities can be used to overwrite files in the filesystem
    with the rights of the user extracting the archive, potentially leading to
    denial of service or privilege escalation. Since LHa is often interfaced to
    other software like an email virus scanner, this attack can be used
    remotely.
  
Workaround :

    There is no known workaround at this time. All users are advised to upgrade
    to the latest available version of LHa."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users of LHa should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv '>=app-arch/lha-114i-r2'
    # emerge '>=app-arch/lha-114i-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:lha");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/09");
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

if (qpkg_check(package:"app-arch/lha", unaffected:make_list("rge 114i-r2"), vulnerable:make_list("rle 114i-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "app-arch/lha");
}
