#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200807-14.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33780);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 14:11:58 $");

  script_cve_id("CVE-2008-1628");
  script_osvdb_id(43912);
  script_xref(name:"GLSA", value:"200807-14");

  script_name(english:"GLSA-200807-14 : Linux Audit: Buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200807-14
(Linux Audit: Buffer overflow)

    A stack-based buffer overflow has been reported in the
    audit_log_user_command() function in the file lib/audit_logging.c when
    processing overly long arguments.
  
Impact :

    A local attacker could execute a specially crafted command on the host
    running Linux Audit, possibly resulting in the execution of arbitrary
    code with the privileges of the user running Linux Audit.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200807-14"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Linux Audit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=sys-process/audit-1.7.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(119,264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:audit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
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

if (qpkg_check(package:"sys-process/audit", unaffected:make_list("ge 1.7.3"), vulnerable:make_list("lt 1.7.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Linux Audit");
}
