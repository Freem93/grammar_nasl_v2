#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2010-2011.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68175);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2010-2955", "CVE-2010-2962", "CVE-2010-3079", "CVE-2010-3084", "CVE-2010-3432", "CVE-2010-3437", "CVE-2010-3442", "CVE-2010-3698", "CVE-2010-3705");

  script_name(english:"Oracle Linux 5 : Unbreakable Enterprise kernel (ELSA-2010-2011)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

Following Security fixes are included in this unbreakable enterprise 
kernel errata:

CVE-2010-3432
The sctp_packet_config function in net/sctp/output.c in the Linux kernel 
before 2.6.35.6 performs extraneous initializations of packet data 
structures, which allows remote attackers to cause a denial of service 
(panic) via a certain sequence of SCTP traffic.
CVE-2010-2962
drivers/gpu/drm/i915/i915_gem.c in the Graphics Execution Manager (GEM) 
in the Intel i915 driver in the Direct Rendering Manager (DRM) subsystem 
in the Linux kernel before 2.6.36 does not properly validate pointers to 
blocks of memory, which allows local users to write to arbitrary kernel 
memory locations, and consequently gain privileges, via crafted use of 
the ioctl interface, related to (1) pwrite and (2) pread operations.
CVE-2010-2955
The cfg80211_wext_giwessid function in net/wireless/wext-compat.c in the 
Linux kernel before 2.6.36-rc3-next-20100831 does not properly 
initialize certain structure members, which allows local users to 
leverage an off-by-one error in the ioctl_standard_iw_point function in 
net/wireless/wext-core.c, and obtain potentially sensitive information 
from kernel heap memory, via vectors involving an SIOCGIWESSID ioctl 
call that specifies a large buffer size.
CVE-2010-3705
The sctp_auth_asoc_get_hmac function in net/sctp/auth.c in the Linux 
kernel before 2.6.36 does not properly validate the hmac_ids array of an 
SCTP peer, which allows remote attackers to cause a denial of service 
(memory corruption and panic) via a crafted value in the last element of 
this array.
CVE-2010-3084
Buffer overflow in the niu_get_ethtool_tcam_all function in 
drivers/net/niu.c in the Linux kernel before 2.6.36-rc4 allows local 
users to cause a denial of service or possibly have unspecified other 
impact via the ETHTOOL_GRXCLSRLALL ethtool command.
CVE-2010-3437
Integer signedness error in the pkt_find_dev_from_minor function in 
drivers/block/pktcdvd.c in the Linux kernel before 2.6.36-rc6 allows 
local users to obtain sensitive information from kernel memory or cause 
a denial of service (invalid pointer dereference and system crash) via a 
crafted index value in a PKT_CTRL_CMD_STATUS ioctl call.
CVE-2010-3079
kernel/trace/ftrace.c in the Linux kernel before 2.6.35.5, when debugfs 
is enabled, does not properly handle interaction between mutex 
possession and llseek operations, which allows local users to cause a 
denial of service (NULL pointer dereference and outage of all function 
tracing files) via an lseek call on a file descriptor associated with 
the set_ftrace_filter file.
CVE-2010-3698
The KVM implementation in the Linux kernel before 2.6.36 does not 
properly reload the FS and GS segment registers, which allows host OS 
users to cause a denial of service (host OS crash) via a KVM_RUN ioctl 
call in conjunction with a modified Local Descriptor Table (LDT).
CVE-2010-3442
Multiple integer overflows in the snd_ctl_new function in 
sound/core/control.c in the Linux kernel before 2.6.36-rc5-next-20100929 
allow local users to cause a denial of service (heap memory corruption) 
or possibly have unspecified other impact via a crafted (1) 
SNDRV_CTL_IOCTL_ELEM_ADD or (2) SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl call.


[2.6.32-100.24.1.el5]
- [sctp] Do not reset the packet during sctp_packet_con[CVE-2010-3432]
- [drm/i915] Sanity check pread/pwrite [CVE-2010-2962]
- [wireless] fix kernel heap content leak [CVE-2010-2955]
- [sctp] Fix out-of-bounds reading in sctp_asoc_get_hmac() [CVE-2010-3705]
- [niu] Fix kernel buffer overflow for ETHTOOL_GRXCLSRLALL [CVE-2010-3084]
- Fix pktcdvd ioctl dev_minor range check [CVE-2010-3437]
- Do not allow llseek to set_ftrace_filter [CVE-2010-3079]
- [kvm] Fix fs/gs reload oops with invalid ldt [CVE-2010-3698]
- [alsa] prevent heap corruption in snd_ctl_new() [CVE-2010-3442]
- Fix LACP bonding mode (Tina Yang)
- Fix grat arps on bonded interfaces (Tina Yang)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-December/001775.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.24.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ofa-2.6.32-100.24.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-devel-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-doc-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-firmware-2.6.32-100.24.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL5", cpu:"x86_64", reference:"kernel-headers-2.6.32-100.24.1.el5")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"ofa-2.6.32-100.24.1.el5-1.5.1-4.0.23")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"ofa-2.6.32-100.24.1.el5debug-1.5.1-4.0.23")) flag++;


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
