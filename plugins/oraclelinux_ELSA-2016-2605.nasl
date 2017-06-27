#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2605 and 
# Oracle Linux Security Advisory ELSA-2016-2605 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94724);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-5011");
  script_osvdb_id(141270);
  script_xref(name:"RHSA", value:"2016:2605");

  script_name(english:"Oracle Linux 7 : util-linux (ELSA-2016-2605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2605 :

An update for util-linux is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The util-linux packages contain a large variety of low-level system
utilities that are necessary for a Linux system to function. Among
others, these include the fdisk configuration tool and the login
program.

Security Fix(es) :

* It was found that util-linux's libblkid library did not properly
handle Extended Boot Record (EBR) partitions when reading MS-DOS
partition tables. An attacker with physical USB access to a protected
machine could insert a storage device with a specially crafted
partition table that could, for example, trigger an infinite loop in
systemd-udevd, resulting in a denial of service on that machine.
(CVE-2016-5011)

Red Hat would like to thank Michael Gruhn for reporting this issue.
Upstream acknowledges Christian Moch as the original reporter.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006492.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libblkid-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libblkid-devel-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmount-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libmount-devel-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libuuid-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libuuid-devel-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"util-linux-2.23.2-33.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"uuidd-2.23.2-33.0.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libblkid / libblkid-devel / libmount / libmount-devel / libuuid / etc");
}
