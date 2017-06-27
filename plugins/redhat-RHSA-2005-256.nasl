#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:256. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18312);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2004-1453");
  script_osvdb_id(9010);
  script_xref(name:"RHSA", value:"2005:256");

  script_name(english:"RHEL 3 : glibc (RHSA-2005:256)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that address several bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The GNU libc packages (known as glibc) contain the standard C
libraries used by applications.

It was discovered that the use of LD_DEBUG, LD_SHOW_AUXV, and
LD_DYNAMIC_WEAK were not restricted for a setuid program. A local user
could utilize this flaw to gain information, such as the list of
symbols used by the program. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-1453 to this
issue.

This erratum addresses the following bugs in the GNU C Library :

  - fix stack alignment in IA-32 clone - fix double free in
    globfree - fix fnmatch to avoid jumping based on
    uninitialized memory read - fix fseekpos after ungetc -
    fix TZ env var handling if the variable ends with + or -
    - avoid depending on values read from uninitialized
    memory in strtold on certain architectures - fix mapping
    alignment computation in dl-load - fix i486+ strncat
    inline assembly - make gethostid/sethostid work on
    bi-arch platforms - fix ppc64 getcontext/swapcontext -
    fix pthread_exit if called after pthread_create, but
    before the created thread actually started - fix return
    values for tgamma (+-0) - fix handling of very long
    lines in /etc/hosts - avoid page aliasing of thread
    stacks on AMD64 - avoid busy loop in malloc if
    concurrent with fork - allow putenv and setenv in shared
    library constructors - fix restoring of CCR in
    swapcontext and getcontext on ppc64 - avoid using
    sigaction (SIGPIPE, ...) in syslog implementation

All users of glibc should upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-256.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:256";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL3", reference:"glibc-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-common-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-devel-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-headers-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-profile-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"glibc-utils-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"nptl-devel-2.3.2-95.33")) flag++;
  if (rpm_check(release:"RHEL3", reference:"nscd-2.3.2-95.33")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-profile / etc");
  }
}
