#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1213 and 
# Oracle Linux Security Advisory ELSA-2013-1213 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69806);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 17:16:04 $");

  script_cve_id("CVE-2013-4169");
  script_xref(name:"RHSA", value:"2013:1213");

  script_name(english:"Oracle Linux 5 : gdm (ELSA-2013-1213)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1213 :

Updated gdm and initscripts packages that fix one security issue are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The GNOME Display Manager (GDM) provides the graphical login screen,
shown shortly after boot up, log out, and when user-switching.

A race condition was found in the way GDM handled the X server sockets
directory located in the system temporary directory. An unprivileged
user could use this flaw to perform a symbolic link attack, giving
them write access to any file, allowing them to escalate their
privileges to root. (CVE-2013-4169)

Note that this erratum includes an updated initscripts package. To fix
CVE-2013-4169, the vulnerable code was removed from GDM and the
initscripts package was modified to create the affected directory
safely during the system boot process. Therefore, this update will
appear on all systems, however systems without GDM installed are not
affected by this flaw.

Red Hat would like to thank the researcher with the nickname vladz for
reporting this issue.

All users should upgrade to these updated packages, which correct this
issue. The system must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-September/003655.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gdm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"gdm-2.16.0-59.0.1.el5_9.1")) flag++;
if (rpm_check(release:"EL5", reference:"gdm-docs-2.16.0-59.0.1.el5_9.1")) flag++;
if (rpm_check(release:"EL5", reference:"initscripts-8.45.42-2.0.1.el5_9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm / gdm-docs / initscripts");
}
