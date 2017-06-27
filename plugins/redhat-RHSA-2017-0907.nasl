#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0907. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99341);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2017-2616");
  script_osvdb_id(152469);
  script_xref(name:"RHSA", value:"2017:0907");

  script_name(english:"RHEL 7 : util-linux (RHSA-2017:0907)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for util-linux is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The util-linux packages contain a large variety of low-level system
utilities that are necessary for a Linux system to function. Among
others, these include the fdisk configuration tool and the login
program.

Security Fix(es) :

* A race condition was found in the way su handled the management of
child processes. A local authenticated attacker could use this flaw to
kill other processes with root privileges under specific conditions.
(CVE-2017-2616)

Red Hat would like to thank Tobias Stockmann for reporting this
issue.

Bug Fix(es) :

* The 'findmnt --target <path>' command prints all file systems where
the mount point directory is <path>. Previously, when used in the
chroot environment, 'findmnt --target <path>' incorrectly displayed
all mount points. The command has been fixed so that it now checks the
mount point path and returns information only for the relevant mount
point. (BZ#1414481)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-2616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0907.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0907";
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
  if (rpm_check(release:"RHEL7", reference:"libblkid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libblkid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libblkid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libblkid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libblkid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libblkid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libmount-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libmount-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libmount-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libmount-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libmount-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libmount-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libuuid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libuuid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libuuid-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libuuid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"libuuid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"libuuid-devel-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"util-linux-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"util-linux-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"util-linux-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"util-linux-debuginfo-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"i686", reference:"util-linux-debuginfo-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", sp:"3", cpu:"x86_64", reference:"util-linux-debuginfo-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"uuidd-2.23.2-33.el7_3.2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"uuidd-2.23.2-33.el7_3.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-devel / libmount / libmount-devel / libuuid / etc");
  }
}
