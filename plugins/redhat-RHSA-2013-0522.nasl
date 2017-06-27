#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0522. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64769);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2011-4355");
  script_xref(name:"RHSA", value:"2013:0522");

  script_name(english:"RHEL 6 : gdb (RHSA-2013:0522)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdb packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The GNU Debugger (GDB) allows debugging of programs written in C, C++,
Java, and other languages by executing them in a controlled fashion
and then printing out their data.

GDB tried to auto-load certain files (such as GDB scripts, Python
scripts, and a thread debugging library) from the current working
directory when debugging programs. This could result in the execution
of arbitrary code with the user's privileges when GDB was run in a
directory that has untrusted content. (CVE-2011-4355)

With this update, GDB no longer auto-loads files from the current
directory and only trusts certain system directories by default. The
list of trusted directories can be viewed and modified using the 'show
auto-load safe-path' and 'set auto-load safe-path' GDB commands. Refer
to the GDB manual, linked to in the References, for further
information.

This update also fixes the following bugs :

* When a struct member was at an offset greater than 256 MB, the
resulting bit position within the struct overflowed and caused an
invalid memory access by GDB. With this update, the code has been
modified to ensure that GDB can access such positions. (BZ#795424)

* When a thread list of the core file became corrupted, GDB did not
print this list but displayed the 'Cannot find new threads: generic
error' error message instead. With this update, GDB has been modified
and it now prints the thread list of the core file as expected.
(BZ#811648)

* GDB did not properly handle debugging of multiple binaries with the
same build ID. This update modifies GDB to use symbolic links created
for particular binaries so that debugging of binaries that share a
build ID now proceeds as expected. Debugging of live programs and core
files is now more user-friendly. (BZ#836966)

All users of gdb are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceware.org/gdb/current/onlinedocs/gdb/"
  );
  # http://sourceware.org/gdb/current/onlinedocs/gdb/Auto_002dloading.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6a7f3c1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0522.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gdb, gdb-debuginfo and / or gdb-gdbserver
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdb-gdbserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0522";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gdb-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gdb-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gdb-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gdb-debuginfo-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gdb-debuginfo-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gdb-debuginfo-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"gdb-gdbserver-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"gdb-gdbserver-7.2-60.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"gdb-gdbserver-7.2-60.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb / gdb-debuginfo / gdb-gdbserver");
  }
}
