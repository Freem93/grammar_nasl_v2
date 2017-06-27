#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200405-20.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(14506);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/04/28 18:42:38 $");

  script_cve_id("CVE-2004-0381", "CVE-2004-0388");
  script_osvdb_id(6420, 6421);
  script_xref(name:"GLSA", value:"200405-20");

  script_name(english:"GLSA-200405-20 : Insecure Temporary File Creation In MySQL");
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
"The remote host is affected by the vulnerability described in GLSA-200405-20
(Insecure Temporary File Creation In MySQL)

    The MySQL bug reporting utility (mysqlbug) creates a temporary file to log
    bug reports to. A malicious local user with write access to the /tmp
    directory could create a symbolic link of the name mysqlbug-N
    pointing to a protected file, such as /etc/passwd, such that when mysqlbug
    creates the Nth log file, it would end up overwriting the target
    file. A similar vulnerability exists with the mysql_multi utility, which
    creates a temporary file called mysql_multi.log.
  
Impact :

    Since mysql_multi runs as root, a local attacker could use this to destroy
    any other users' data or corrupt and destroy system files.
  
Workaround :

    One could modify both scripts to log to a directory that users do not have
    write permission to, such as /var/log/mysql/."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200405-20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All users should upgrade to the latest stable version of MySQL.
    # emerge sync
    # emerge -pv '>=dev-db/mysql-4.0.18-r2'
    # emerge '>=dev-db/mysql-4.0.18-r2'"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"dev-db/mysql", unaffected:make_list("ge 4.0.18-r2"), vulnerable:make_list("lt 4.0.18-r2"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dev-db/mysql");
}
