#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2401. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86989);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-5281");
  script_osvdb_id(130500);
  script_xref(name:"RHSA", value:"2015:2401");

  script_name(english:"RHEL 7 : grub2 (RHSA-2015:2401)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated grub2 packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The grub2 packages provide version 2 of the Grand Unified Bootloader
(GRUB), a highly configurable and customizable bootloader with modular
architecture. The packages support a variety of kernel formats, file
systems, computer architectures, and hardware devices.

It was discovered that grub2 builds for EFI systems contained modules
that were not suitable to be loaded in a Secure Boot environment. An
attacker could use this flaw to circumvent the Secure Boot mechanisms
and load non-verified code. Attacks could use the boot menu if no
password was set, or the grub2 configuration file if the attacker has
root privileges on the system. (CVE-2015-5281)

This update also fixes the following bugs :

* In one of the earlier updates, GRUB2 was modified to escape forward
slash (/) characters in several different places. In one of these
places, the escaping was unnecessary and prevented certain types of
kernel command-line arguments from being passed to the kernel
correctly. With this update, GRUB2 no longer escapes the forward slash
characters in the mentioned place, and the kernel command-line
arguments work as expected. (BZ#1125404)

* Previously, GRUB2 relied on a timing mechanism provided by legacy
hardware, but not by the Hyper-V Gen2 hypervisor, to calibrate its
timer loop. This prevented GRUB2 from operating correctly on Hyper-V
Gen2. This update modifies GRUB2 to use a different mechanism on
Hyper-V Gen2 to calibrate the timing. As a result, Hyper-V Gen2
hypervisors now work as expected. (BZ#1150698)

* Prior to this update, users who manually configured GRUB2 to use the
built-in GNU Privacy Guard (GPG) verification observed the following
error on boot :

alloc magic is broken at [addr]: [value] Aborted.

Consequently, the boot failed. The GRUB2 built-in GPG verification has
been modified to no longer free the same memory twice. As a result,
the mentioned error no longer occurs. (BZ#1167977)

* Previously, the system sometimes did not recover after terminating
unexpectedly and failed to reboot. To fix this problem, the GRUB2
packages now enforce file synchronization when creating the GRUB2
configuration file, which ensures that the required configuration
files are written to disk. As a result, the system now reboots
successfully after crashing. (BZ#1212114)

* Previously, if an unconfigured network driver instance was selected
and configured when the GRUB2 bootloader was loaded on a different
instance, GRUB2 did not receive notifications of the Address
Resolution Protocol (ARP) replies. Consequently, GRUB2 failed with the
following error message :

error: timeout: could not resolve hardware address.

With this update, GRUB2 selects the network driver instance from which
it was loaded. As a result, ARP packets are processed correctly.
(BZ#1257475)

In addition, this update adds the following enhancement :

* Sorting of GRUB2 boot menu has been improved. GRUB2 now uses the
rpmdevtools package to sort available kernels and the configuration
file is being generated correctly with the most recent kernel version
listed at the top. (BZ#1124074)

All grub2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5281.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2401.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2401";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grub2-2.02-0.29.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grub2-debuginfo-2.02-0.29.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grub2-efi-2.02-0.29.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grub2-efi-modules-2.02-0.29.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"grub2-tools-2.02-0.29.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "grub2 / grub2-debuginfo / grub2-efi / grub2-efi-modules / etc");
  }
}
