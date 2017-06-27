#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1843 and 
# CentOS Errata and Security Advisory 2014:1843 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79189);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-3185", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646");
  script_bugtraq_id(69781, 70743, 70745, 70746);
  script_osvdb_id(110732, 113731);
  script_xref(name:"RHSA", value:"2014:1843");

  script_name(english:"CentOS 6 : kernel (CESA-2014:1843)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A race condition flaw was found in the way the Linux kernel's KVM
subsystem handled PIT (Programmable Interval Timer) emulation. A guest
user who has access to the PIT I/O ports could use this flaw to crash
the host. (CVE-2014-3611, Important)

* A memory corruption flaw was found in the way the USB ConnectTech
WhiteHEAT serial driver processed completion commands sent via USB
Request Blocks buffers. An attacker with physical access to the system
could use this flaw to crash the system or, potentially, escalate
their privileges on the system. (CVE-2014-3185, Moderate)

* It was found that the Linux kernel's KVM subsystem did not handle
the VM exits gracefully for the invept (Invalidate Translations
Derived from EPT) and invvpid (Invalidate Translations Based on VPID)
instructions. On hosts with an Intel processor and invept/invppid VM
exit support, an unprivileged guest user could use these instructions
to crash the guest. (CVE-2014-3645, CVE-2014-3646, Moderate)

Red Hat would like to thank Lars Bull of Google for reporting
CVE-2014-3611, and the Advanced Threat Research team at Intel Security
for reporting CVE-2014-3645 and CVE-2014-3646.

This update also fixes the following bugs :

* This update fixes several race conditions between PCI error recovery
callbacks and potential calls of the ifup and ifdown commands in the
tg3 driver. When triggered, these race conditions could cause a kernel
crash. (BZ#1142570)

* Previously, GFS2 failed to unmount a sub-mounted GFS2 file system if
its parent was also a GFS2 file system. This problem has been fixed by
adding the appropriate d_op->d_hash() routine call for the last
component of the mount point path in the path name lookup mechanism
code (namei). (BZ#1145193)

* Due to previous changes in the virtio-net driver, a Red Hat
Enterprise Linux 6.6 guest was unable to boot with the 'mgr_rxbuf=off'
option specified. This was caused by providing the page_to_skb()
function with an incorrect packet length in the driver's Rx path. This
problem has been fixed and the guest in the described scenario can now
boot successfully. (BZ#1148693)

* When using one of the newer IPSec Authentication Header (AH)
algorithms with Openswan, a kernel panic could occur. This happened
because the maximum truncated ICV length was too small. To fix this
problem, the MAX_AH_AUTH_LEN parameter has been set to 64.
(BZ#1149083)

* A bug in the IPMI driver caused the kernel to panic when an IPMI
interface was removed using the hotmod script. The IPMI driver has
been fixed to properly clean the relevant data when removing an IPMI
interface. (BZ#1149578)

* Due to a bug in the IPMI driver, the kernel could panic when adding
an IPMI interface that was previously removed using the hotmod script.
This update fixes this bug by ensuring that the relevant shadow
structure is initialized at the right time. (BZ#1149580)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72b27548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-504.1.3.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-504.1.3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
