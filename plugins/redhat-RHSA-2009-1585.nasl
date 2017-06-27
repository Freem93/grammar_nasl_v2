#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1585. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63900);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/03 17:27:03 $");

  script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_bugtraq_id(36363, 36572, 36573);
  script_xref(name:"RHSA", value:"2009:1585");

  script_name(english:"RHEL 5 : samba3x (RHSA-2009:1585)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x packages that fix multiple security issues and various
bugs are now available for Red Hat Enterprise Linux 5 Supplementary.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Samba is a suite of programs used by machines to share files,
printers, and other information. These samba3x packages provide Samba
3.3, which is a Technology Preview for Red Hat Enterprise Linux 5.
These packages cannot be installed in parallel with the samba
packages. Note: Technology Previews are not intended for production
use.

A denial of service flaw was found in the Samba smbd daemon. An
authenticated, remote user could send a specially crafted response
that would cause an smbd child process to enter an infinite loop. An
authenticated, remote user could use this flaw to exhaust system
resources by opening multiple CIFS sessions. (CVE-2009-2906)

An uninitialized data access flaw was discovered in the smbd daemon
when using the non-default 'dos filemode' configuration option in
'smb.conf'. An authenticated, remote user with write access to a file
could possibly use this flaw to change an access control list for that
file, even when such access should have been denied. (CVE-2009-1888)

A flaw was discovered in the way Samba handled users without a home
directory set in the back-end password database (e.g. '/etc/passwd').
If a share for the home directory of such a user was created (e.g.
using the automated '[homes]' share), any user able to access that
share could see the whole file system, possibly bypassing intended
access restrictions. (CVE-2009-2813)

The mount.cifs program printed CIFS passwords as part of its debug
output when running in verbose mode. When mount.cifs had the setuid
bit set, a local, unprivileged user could use this flaw to disclose
passwords from a file that would otherwise be inaccessible to that
user. Note: mount.cifs from the samba3x packages distributed by Red
Hat does not have the setuid bit set. This flaw only affected systems
where the setuid bit was manually set by an administrator.
(CVE-2009-2948)

This update also fixes the following bugs :

* the samba3x packages contained missing and conflicting license
information. License information was missing for the libtalloc,
libtdb, and tdb-tools packages. The samba3x-common package provided a
COPYING file; however, it stated the license was GPLv2, while RPM
metadata stated the licenses were either GPLv3 or LGPLv3. This update
adds the correct licensing information to the samba3x-common,
libsmbclient, libtalloc, libtdb, and tdb-tools packages. (BZ#528633)

* the upstream Samba version in the samba3x packages distributed with
the RHEA-2009:1399 update contained broken implementations of the
Netlogon credential chain and SAMR access checks security subsystems.
This prevented Samba from acting as a domain controller: Client
systems could not join the domain; users could not authenticate; and
systems could not access the user and group list. (BZ#524551)

* this update resolves interoperability issues with Windows 7 and
Windows Server 2008 R2. (BZ#529022)

These packages upgrade Samba from version 3.3.5 to version 3.3.8.
Refer to the Samba Release Notes for a list of changes between
versions: http://samba.org/samba/history/

Users of samba3x should upgrade to these updated packages, which
resolve these issues. After installing this update, the smb service
will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/support/policy/soc/production/preview_scope/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://samba.org/samba/history/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1585.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5\.4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.4", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1585";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libsmbclient-3.0.34-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libsmbclient-devel-3.0.34-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libtalloc-1.2.0-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libtalloc-devel-1.2.0-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libtdb-1.1.2-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"libtdb-devel-1.1.2-46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-client-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-common-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-doc-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-swat-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-winbind-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba3x-winbind-devel-3.3.8-0.46.el5")) flag++;
  if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"tdb-tools-1.1.2-46.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / libtalloc / libtalloc-devel / etc");
  }
}
