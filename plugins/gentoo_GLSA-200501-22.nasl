#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200501-22.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(16413);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/13 13:41:57 $");

  script_cve_id("CVE-2005-0002");
  script_osvdb_id(12896);
  script_xref(name:"GLSA", value:"200501-22");

  script_name(english:"GLSA-200501-22 : poppassd_pam: Unauthorized password changing");
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
"The remote host is affected by the vulnerability described in GLSA-200501-22
(poppassd_pam: Unauthorized password changing)

    Gentoo Linux developer Marcus Hanwell discovered that poppassd_pam
    did not check that the old password was valid before changing
    passwords. Our investigation revealed that poppassd_pam did not call
    pam_authenticate before calling pam_chauthtok.
  
Impact :

    A remote attacker could change the system password of any user,
    including root. This leads to a complete compromise of the POP
    accounts, and may also lead to a complete root compromise of the
    affected server, if it also provides shell access authenticated using
    system passwords.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200501-22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All poppassd_pam users should migrate to the new package called
    poppassd_ceti:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-mail/poppassd_ceti-1.8.4'
    Note: Portage will automatically replace the poppassd_pam
    package by the poppassd_ceti package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:poppassd_ceti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:poppassd_pam");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-mail/poppassd_pam", unaffected:make_list(), vulnerable:make_list("le 1.0"))) flag++;
if (qpkg_check(package:"net-mail/poppassd_ceti", unaffected:make_list("ge 1.8.4"), vulnerable:make_list("le 1.0"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppassd_pam");
}
