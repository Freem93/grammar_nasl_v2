#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2623 and 
# Oracle Linux Security Advisory ELSA-2015-2623 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87395);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 19:11:31 $");

  script_cve_id("CVE-2015-8370");
  script_osvdb_id(131484);
  script_xref(name:"RHSA", value:"2015:2623");

  script_name(english:"Oracle Linux 7 : grub2 (ELSA-2015-2623)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2623 :

Updated grub2 packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

[Updated 27 January 2016] This advisory has been updated to document
additional steps that need to be performed on BIOS-based systems after
installing this update. No changes were made to the packages included
in the advisory.

The grub2 packages provide version 2 of the Grand Unified Bootloader
(GRUB), a highly configurable and customizable bootloader with modular
architecture. The packages support a variety of kernel formats, file
systems, computer architectures, and hardware devices.

A flaw was found in the way the grub2 handled backspace characters
entered in username and password prompts. An attacker with access to
the system console could use this flaw to bypass grub2 password
protection and gain administrative access to the system.
(CVE-2015-8370)

This update also fixes the following bug :

* When upgrading from Red Hat Enterprise Linux 7.1 and earlier, a
configured boot password was not correctly migrated to the newly
introduced user.cfg configuration files. This could possibly prevent
system administrators from changing grub2 configuration during system
boot even if they provided the correct password. This update corrects
the password migration script and the incorrectly generated user.cfg
file. (BZ#1290089)

All grub2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For this
update to take effect on BIOS-based machines, grub2 needs to be
reinstalled as documented in the 'Reinstalling GRUB 2 on BIOS-Based
Machines' section of the Red Hat Enterprise Linux 7 System
Administrator's Guide linked to in the References section. No manual
action is needed on UEFI-based machines."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-December/005630.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected grub2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-efi-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"grub2-2.02-0.33.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"grub2-efi-2.02-0.33.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"grub2-efi-modules-2.02-0.33.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"grub2-tools-2.02-0.33.0.1.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-efi / grub2-efi-modules / grub2-tools");
}
