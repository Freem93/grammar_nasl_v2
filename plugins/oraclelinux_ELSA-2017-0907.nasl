#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:0907 and 
# Oracle Linux Security Advisory ELSA-2017-0907 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99330);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/17 14:16:27 $");

  script_cve_id("CVE-2017-2616");
  script_osvdb_id(152469);
  script_xref(name:"RHSA", value:"2017:0907");

  script_name(english:"Oracle Linux 7 : util-linux (ELSA-2017-0907)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:0907 :

An update for util-linux is now available for Red Hat Enterprise Linux
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
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006840.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libblkid-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libblkid-devel-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmount-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmount-devel-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libuuid-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libuuid-devel-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"util-linux-2.23.2-33.0.1.el7_3.2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"uuidd-2.23.2-33.0.1.el7_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-devel / libmount / libmount-devel / libuuid / etc");
}
