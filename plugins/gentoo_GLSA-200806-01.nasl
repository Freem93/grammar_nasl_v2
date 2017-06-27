#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200806-01.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(33084);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 14:04:26 $");

  script_cve_id("CVE-2008-2357");
  script_osvdb_id(45350);
  script_xref(name:"GLSA", value:"200806-01");

  script_name(english:"GLSA-200806-01 : mtr: Stack-based buffer overflow");
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
"The remote host is affected by the vulnerability described in GLSA-200806-01
(mtr: Stack-based buffer overflow)

    Adam Zabrocki reported a boundary error within the split_redraw()
    function in the file split.c, possibly leading to a stack-based buffer
    overflow.
  
Impact :

    A remote attacker could use a specially crafted resolved hostname to
    execute arbitrary code with root privileges. However, it is required
    that the attacker controls the DNS server used by the victim, and that
    the '-p' (or '--split') command line option is used.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200806-01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All mtr users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-analyzer/mtr-0.73-r1'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mtr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/04");
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

if (qpkg_check(package:"net-analyzer/mtr", unaffected:make_list("ge 0.73-r1"), vulnerable:make_list("lt 0.73-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mtr");
}
