#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0987 and 
# CentOS Errata and Security Advisory 2015:0987 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83417);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2015-3331");
  script_bugtraq_id(74235);
  script_osvdb_id(121011);
  script_xref(name:"RHSA", value:"2015:0987");

  script_name(english:"CentOS 7 : kernel (CESA-2015:0987)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A buffer overflow flaw was found in the way the Linux kernel's Intel
AES-NI instructions optimized version of the RFC4106 GCM mode
decryption functionality handled fragmented packets. A remote attacker
could use this flaw to crash, or potentially escalate their privileges
on, a system over a connection with an active AEC-GCM mode IPSec
security association. (CVE-2015-3331, Important)

This update also fixes the following bugs :

* Previously, the kernel audit subsystem did not correctly track file
path names which could lead to empty, or '(null)' path names in the
PATH audit records. This update fixes the bug by correctly tracking
file path names and displaying the names in the audit PATH records.
(BZ#1197746)

* Due to a change in the internal representation of field types,
AUDIT_LOGINUID set to -1 (4294967295) by the audit API was
asymmetrically converted to an AUDIT_LOGINUID_SET field with a value
of 0, unrecognized by an older audit API. To fix this bug, the kernel
takes note about the way the rule has been formulated and reports the
rule in the originally given form. As a result, older versions of
audit provide a report as expected, in the AUDIT_LOGINUID field type
form, whereas the newer versions can migrate to the new
AUDIT_LOGINUID_SET filed type. (BZ#1197748)

* The GFS2 file system 'Splice Read' operation, which is used for the
sendfile() function, was not properly allocating a required
multi-block reservation structure in memory. Consequently, when the
GFS2 block allocator was called to assign blocks of data, it attempted
to dereference the structure, which resulted in a kernel panic. With
this update, 'Splice read' operation properly allocates the necessary
reservation structure in memory prior to calling the block allocator,
and sendfile() thus works properly for GFS2. (BZ#1201256)

* Moving an Open vSwitch (OVS) internal vport to a different net name
space and subsequently deleting that name space led to a kernel panic.
This bug has been fixed by removing the OVS internal vport at net name
space deletion. (BZ#1202357)

* Previously, the kernel audit subsystem was not correctly handling
file and directory moves, leading to audit records that did not match
the audit file watches. This fix correctly handles moves such that the
audit file watches work correctly. (BZ#1202358)

* Due to a regression, the crypto adapter could not be set online. A
patch has been provided that fixes the device registration process so
that the device can be used also before the registration process is
completed, thus fixing this bug. (BZ#1205300)

* Due to incorrect calculation for entropy during the entropy
addition, the amount of entropy in the /dev/random file could be
overestimated. The formula for the entropy addition has been changed,
thus fixing this bug. (BZ#1211288)

* Previously, the ansi_cprng and drbg utilities did not obey the call
convention and returned the positive value on success instead of the
correct value of zero. Consequently, Internet Protocol Security
(IPsec) terminated unexpectedly when ansi_cprng or drbg were used.
With this update, ansi_cprng and drbg have been changed to return zero
on success, and IPsec now functions correctly. (BZ#1211487)

* Due to a failure to clear the timestamp flag when reusing a tx
descriptor in the mlx4_en driver, programs that did not request a
hardware timestamp packet on their sent data received it anyway,
resulting in unexpected behavior in certain applications. With this
update, when reusing the tx descriptor in the mlx4_en driver in the
aforementioned situation, the hardware timestamp flag is cleared, and
applications now behave as expected. (BZ#1209240)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021138.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-229.4.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-229.4.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
