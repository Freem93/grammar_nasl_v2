#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1205. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100142);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2016-9603", "CVE-2017-2633", "CVE-2017-7718", "CVE-2017-7980");
  script_osvdb_id(152424, 153753, 155921, 156069);
  script_xref(name:"RHSA", value:"2017:1205");

  script_name(english:"RHEL 6 : qemu-kvm-rhev (RHSA-2017:1205)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qemu-kvm-rhev is now available for RHEV 3.X Hypervisor
and Agents for RHEL-6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on a variety of architectures. The qemu-kvm-rhev packages
provide the user-space component for running virtual machines that use
KVM in environments managed by Red Hat products.

Security Fix(es) :

* A heap buffer overflow flaw was found in QEMU's Cirrus CLGD 54xx VGA
emulator's VNC display driver support; the issue could occur when a
VNC client attempted to update its display after a VGA operation is
performed by a guest. A privileged user/process inside a guest could
use this flaw to crash the QEMU process or, potentially, execute
arbitrary code on the host with privileges of the QEMU process.
(CVE-2016-9603)

* Quick Emulator (QEMU) built with the Cirrus CLGD 54xx VGA Emulator
support is vulnerable to an out-of-bounds r/w access issue. The
vulnerability could occur while copying VGA data via various bitblt
functions. A privileged user inside the guest could use this flaw to
crash the QEMU process (DoS) or potentially execute arbitrary code on
a host with privileges of the host's QEMU process. (CVE-2017-7980)

* Quick Emulator (QEMU) built with the VNC display driver support is
vulnerable to an out-of-bounds memory access issue. The vulnerability
could occur while refreshing the VNC display surface area in the
'vnc_refresh_server_surface'. A user/process inside the guest could
use this flaw to crash the QEMU process, resulting in a DoS.
(CVE-2017-2633)

* Quick Emulator (QEMU) built with the Cirrus CLGD 54xx VGA Emulator
support is vulnerable to an out-of-bounds access issue. The
vulnerability could occur while copying VGA data using bitblt
functions (for example, cirrus_bitblt_rop_fwd_transp_). A privileged
user inside a guest could use this flaw to crash the QEMU process,
resulting in DoS. (CVE-2017-7718)

Red Hat would like to thank Jiangxin (PSIRT Huawei Inc.) Li Qiang
(Qihoo 360 Gear Team) for reporting CVE-2017-7980 and Jiangxin (PSIRT
Huawei Inc.) for reporting CVE-2017-7718."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9603.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-2633.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7980.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1205.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2017:1205";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-img-rhev-0.12.1.2-2.503.el6_9.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-0.12.1.2-2.503.el6_9.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-debuginfo-0.12.1.2-2.503.el6_9.3")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-rhev-tools-0.12.1.2-2.503.el6_9.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img-rhev / qemu-kvm-rhev / qemu-kvm-rhev-debuginfo / etc");
  }
}
