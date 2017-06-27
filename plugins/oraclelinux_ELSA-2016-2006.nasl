#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2006 and 
# Oracle Linux Security Advisory ELSA-2016-2006 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(93857);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-4470", "CVE-2016-5829");
  script_osvdb_id(140046, 140558);
  script_xref(name:"RHSA", value:"2016:2006");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2016-2006)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2006 :

An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* A flaw was found in the Linux kernel's keyring handling code, where
in key_reject_and_link() an uninitialized variable would eventually
lead to arbitrary free address which could allow attacker to use a
use-after-free style attack. (CVE-2016-4470, Important)

* A heap-based buffer overflow vulnerability was found in the Linux
kernel's hiddev driver. This flaw could allow a local attacker to
corrupt kernel memory, possible privilege escalation or crashing the
system. (CVE-2016-5829, Moderate)

The CVE-2016-4470 issue was discovered by David Howells (Red Hat
Inc.).

Bug Fix(es) :

* Previously, when two NFS shares with different security settings
were mounted, the I/O operations to the kerberos-authenticated mount
caused the RPC_CRED_KEY_EXPIRE_SOON parameter to be set, but the
parameter was not unset when performing the I/O operations on the
sec=sys mount. Consequently, writes to both NFS shares had the same
parameters, regardless of their security settings. This update fixes
this problem by moving the NO_CRKEY_TIMEOUT parameter to the
auth->au_flags field. As a result, NFS shares with different security
settings are now handled as expected. (BZ#1366962)

* In some circumstances, resetting a Fibre Channel over Ethernet
(FCoE) interface could lead to a kernel panic, due to invalid
information extracted from the FCoE header. This update adds santiy
checking to the cpu number extracted from the FCoE header. This
ensures that subsequent operations address a valid cpu, and eliminates
the kernel panic. (BZ#1359036)

* Prior to this update, the following problems occurred with the way
GSF2 transitioned files and directories from the 'unlinked' state to
the 'free' state :

The numbers reported for the df and the du commands in some cases got
out of sync, which caused blocks in the file system to appear missing.
The blocks were not actually missing, but they were left in the
'unlinked' state.

In some circumstances, GFS2 referenced a cluster lock that was already
deleted, which led to a kernel panic.

If an object was deleted and its space reused as a different object,
GFS2 sometimes deleted the existing one, which caused file system
corruption.

With this update, the transition from 'unlinked' to 'free' state has
been fixed. As a result, none of these three problems occur anymore.
(BZ#1359037)

* Previously, the GFS2 file system in some cases became unresponsive
due to lock dependency problems between inodes and the cluster lock.
This occurred most frequently on nearly full file systems where files
and directories were being deleted and recreated at the same block
location at the same time. With this update, a set of patches has been
applied to fix these lock dependencies. As a result, GFS2 no longer
hangs in the described circumstances. (BZ#1359038)

* When used with controllers that do not support DCMD-
MR_DCMD_PD_LIST_QUERY, the megaraid_sas driver can go into infinite
error reporting loop of error reporting messages. This could cause
difficulties with finding other important log messages, or even it
could cause the disk to overflow. This bug has been fixed by ignoring
the DCMD MR_DCMD_PD_LIST_QUERY query for controllers which do not
support it and sending the DCMD SUCCESS status to the AEN functions.
As a result, the error messages no longer appear when there is a
change in the status of one of the arrays. (BZ#1359039)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-October/006394.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-abi-whitelists-2.6.32") && rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-642.6.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-642.6.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-642.6.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-642.6.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
