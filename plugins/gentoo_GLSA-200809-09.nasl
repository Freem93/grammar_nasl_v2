#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200809-09.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(34248);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:11:58 $");

  script_cve_id("CVE-2008-3889");
  script_osvdb_id(48108);
  script_xref(name:"GLSA", value:"200809-09");

  script_name(english:"GLSA-200809-09 : Postfix: Denial of Service");
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
"The remote host is affected by the vulnerability described in GLSA-200809-09
(Postfix: Denial of Service)

    It has been discovered than Postfix leaks an epoll file descriptor when
    executing external commands, e.g. user-controlled $HOME/.forward or
    $HOME/.procmailrc files. NOTE: This vulnerability only concerns Postfix
    instances running on Linux 2.6 kernels.
  
Impact :

    A local attacker could exploit this vulnerability to reduce the
    performance of Postfix, and possibly trigger an assertion, resulting in
    a Denial of Service.
  
Workaround :

    Allow only trusted users to control delivery to non-Postfix commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200809-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Postfix 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.4.9'
    All Postfix 2.5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-mta/postfix-2.5.5'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:postfix");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"mail-mta/postfix", unaffected:make_list("ge 2.4.9", "ge 2.5.5"), vulnerable:make_list("lt 2.4.9", "lt 2.5.5"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:qpkg_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Postfix");
}
