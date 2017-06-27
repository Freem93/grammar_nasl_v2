#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1754. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78981);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4344");
  script_bugtraq_id(62773);
  script_osvdb_id(98028);
  script_xref(name:"RHSA", value:"2013:1754");

  script_name(english:"RHEL 6 : qemu-kvm-rhev, qemu-kvm-rhev-tools, qemu-img-rhev (RHSA-2013:1754)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm-rhev, qemu-kvm-rhev-tools, and qemu-img-rhev packages
are now available.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm-rhev package
provides the user-space component for running virtual machines using
KVM, in environments managed by Red Hat Enterprise Virtualization
Manager.

A buffer overflow flaw was found in the way QEMU processed the SCSI
'REPORT LUNS' command when more than 256 LUNs were specified for a
single SCSI target. A privileged guest user could use this flaw to
corrupt QEMU process memory on the host, which could potentially
result in arbitrary code execution on the host with the privileges of
the QEMU process. (CVE-2013-4344)

This issue was discovered by Asias He of Red Hat.

This update fixes the following bugs :

* In QMP monitor, if an attempt was made to create an image with the
same file name as the backing file, an error was generated, but no
message was displayed. Performing this action in QMP Monitor now
generates the same error message as performing the action in HMP:
'Error: Trying to create an image with the same file name as the
backing file'. (BZ#877240)

* QEMU I/O throttling has been disabled in Red Hat Enterprise Linux
and is now only available enabled in the Red Hat Enterprise
Virtualization QEMU package (qemu-kvm-rhev). (BZ#975468)

* When booting a guest machine, it would still boot when specifying
iops and bps as a negative value, without displaying an error message.
This has been fixed so that if a negative value is used the guest does
not boot and QEMU exits with the following message 'bps and iops
values must be 0 or greater'. (BZ#987725)

* When booting a guest with QMP server, hot plug was failing. It can
now do hotplug with QEMU I/O throttling including iops, iops_wr,
iops_rd, bps, bps_wr, bps_rd inofs successfully. (BZ#987745)

* Due to a change in virtualization features, all fixes and errata
related to Red Hat Enterprise Virtualization specific features, can
only be posted to the Red Hat Enterprise Virtualization channel.
Therefore a Red Hat Enterprise Virtualization specific qemu-kvm (for
RHEV-H-6.5.0 Errata) was developed. This meant that the qemu-kvm-rhev
binary was mapped to a Red Had enterprise Virtualization channel,
entitled to Red Hat Enterprise Virtualization customers, and disabled
from the Red Hat Enterprise Linux channel. (BZ#997032)

* The qemu-kvm-rhev package now contains /usr/lib64/qemu, as this
directory is where CEPH packages provide librbd to be used by QEMU at
runtime. (BZ#999705)

* QEMU performed a core dump when iops.bps was set to a negative
value. This has been fixed so that it no longer performs a core dump
when a negative value is entered, instead an error message is
displayed indicating the values must be zero of greater. (BZ#1001436)

* When running the 'rpm -V qemu-kvm-rhev' command, an error was
generated stating there were unsatisfied dependencies. This has been
fixed so there now are no unsatisfied dependencies and it executes
correctly. (BZ#1010930)

In addition, this update adds the following enhancements :

* QEMU I/O throttling allows for finer control of the rate of I/O
operations at the QEMU level, and is therefore independent of the
underlying storage device. A similar feature can be created by using
cgroups at the libvirt level, but cgroups is limited as it does not
support some storage devices (such as image files over NFS) and
throttles the whole virtual machine, including access to meta-data,
while qemu I/O is more fine-grained. (BZ#956825)

* Patches were added to the QEMU block driver for accessing CEPH
storage on qemu-kvm-rhev. However,this is not usable on its own, a
librbd library still needs to be provided. The librbd library is not
provided in Red Hat Enterprise Linux and will be handled by a third
party source. (BZ#988079)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4344.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1754.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1754";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-img-rhev-0.12.1.2-2.415.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-0.12.1.2-2.415.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-debuginfo-0.12.1.2-2.415.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-tools-0.12.1.2-2.415.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img-rhev / qemu-kvm-rhev / qemu-kvm-rhev-debuginfo / etc");
  }
}
