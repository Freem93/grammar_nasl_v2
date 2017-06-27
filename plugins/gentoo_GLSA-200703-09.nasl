#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200703-09.
#
# The advisory text is Copyright (C) 2001-2015 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(24801);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/13 13:56:53 $");

  script_cve_id("CVE-2007-0472", "CVE-2007-0473", "CVE-2007-0474", "CVE-2007-0475");
  script_osvdb_id(32981, 32982, 32983, 32984);
  script_xref(name:"GLSA", value:"200703-09");

  script_name(english:"GLSA-200703-09 : Smb4K: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-200703-09
(Smb4K: Multiple vulnerabilities)

    Kees Cook of the Ubuntu Security Team has identified multiple
    vulnerabilities in Smb4K.
    The writeFile() function of
    smb4k/core/smb4kfileio.cpp makes insecure usage of temporary
    files.
    The writeFile() function also stores the contents of
    the sudoers file with incorrect permissions, allowing for the file's
    contents to be world-readable.
    The createLockFile() and
    removeLockFile() functions improperly handle lock files, possibly
    allowing for a race condition in file handling.
    The smb4k_kill
    utility distributed with Smb4K allows any user in the sudoers group to
    kill any process on the system.
    Lastly, there is the potential
    for multiple stack overflows when any Smb4K utility is used with the
    sudo command.
  
Impact :

    A local attacker could gain unauthorized access to arbitrary files via
    numerous attack vectors. In some cases to obtain this unauthorized
    access, an attacker would have to be a member of the sudoers list.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200703-09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Smb4K users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-misc/smb4k-0.6.10a'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:smb4k");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"net-misc/smb4k", unaffected:make_list("ge 0.6.10a"), vulnerable:make_list("lt 0.6.10a"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Smb4K");
}
