#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200409-27.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14790);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/13 13:34:22 $");

  script_xref(name:"GLSA", value:"200409-27");

  script_name(english:"GLSA-200409-27 : glFTPd: Local buffer overflow vulnerability");
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
"The remote host is affected by the vulnerability described in GLSA-200409-27
(glFTPd: Local buffer overflow vulnerability)

    The glFTPd server is vulnerable to a buffer overflow in the 'dupescan'
    program. This vulnerability is due to an unsafe strcpy() call which can
    cause the program to crash when a large argument is passed.
  
Impact :

    A local user with malicious intent can pass a parameter to the dupescan
    program that exceeds the size of the buffer, causing it to overflow. This
    can lead the program to crash, and potentially allow arbitrary code
    execution with the permissions of the user running glFTPd, which could be
    the root user.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/375775/2004-09-17/2004-09-23/0"
  );
  # http://www.glftpd.com/modules.php?op=modload&name=News&file=article&sid=23&mode=thread&order=0&thold=0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8a4e533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200409-27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All glFTPd users should upgrade to the latest version:
    # emerge sync
    # emerge -pv '>=net-ftp/glftpd-1.32-r1'
    # emerge '>=net-ftp/glftpd-1.32-r1'"
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:glftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/22");
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

if (qpkg_check(package:"net-ftp/glftpd", unaffected:make_list("ge 1.32-r1"), vulnerable:make_list("lt 1.32-r1"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glFTPd");
}
