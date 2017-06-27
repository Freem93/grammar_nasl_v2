#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1064 and 
# CentOS Errata and Security Advisory 2012:1064 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59949);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/11 13:39:37 $");

  script_cve_id("CVE-2012-2744", "CVE-2012-2745");
  script_osvdb_id(83665, 83666);
  script_xref(name:"RHSA", value:"2012:1064");

  script_name(english:"CentOS 6 : kernel (CESA-2012:1064)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A NULL pointer dereference flaw was found in the nf_ct_frag6_reasm()
function in the Linux kernel's netfilter IPv6 connection tracking
implementation. A remote attacker could use this flaw to send
specially crafted packets to a target system that is using IPv6 and
also has the nf_conntrack_ipv6 kernel module loaded, causing it to
crash. (CVE-2012-2744, Important)

* A flaw was found in the way the Linux kernel's key management
facility handled replacement session keyrings on process forks. A
local, unprivileged user could use this flaw to cause a denial of
service. (CVE-2012-2745, Moderate)

Red Hat would like to thank an anonymous contributor working with the
Beyond Security SecuriTeam Secure Disclosure program for reporting
CVE-2012-2744.

This update also fixes the following bugs :

* Previously introduced firmware files required for new Realtek
chipsets contained an invalid prefix ('rtl_nic_') in the file names,
for example '/lib/firmware/rtl_nic/rtl_nic_rtl8168d-1.fw'. This update
corrects these file names. For example, the aforementioned file is now
correctly named '/lib/firmware/rtl_nic/rtl8168d-1.fw'. (BZ#832359)

* This update blacklists the ADMA428M revision of the 2GB ATA Flash
Disk device. This is due to data corruption occurring on the said
device when the Ultra-DMA 66 transfer mode is used. When the
'libata.force=5:pio0,6:pio0' kernel parameter is set, the
aforementioned device works as expected. (BZ#832363)

* On Red Hat Enterprise Linux 6, mounting an NFS export from a Windows
2012 server failed due to the fact that the Windows server contains
support for the minor version 1 (v4.1) of the NFS version 4 protocol
only, along with support for versions 2 and 3. The lack of the minor
version 0 (v4.0) support caused Red Hat Enterprise Linux 6 clients to
fail instead of rolling back to version 3 as expected. This update
fixes this bug and mounting an NFS export works as expected.
(BZ#832365)

* On ext4 file systems, when fallocate() failed to allocate blocks due
to the ENOSPC condition (no space left on device) for a file larger
than 4 GB, the size of the file became corrupted and, consequently,
caused file system corruption. This was due to a missing cast operator
in the 'ext4_fallocate()' function. With this update, the underlying
source code has been modified to address this issue, and file system
corruption no longer occurs. (BZ#833034)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018731.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7433e41"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-279.1.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-279.1.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
