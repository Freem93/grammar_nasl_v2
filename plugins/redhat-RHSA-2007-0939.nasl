#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0939. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27616);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2006-6921", "CVE-2007-2878", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4571");
  script_bugtraq_id(25216, 25244, 25348, 25387, 25672, 25807);
  script_osvdb_id(35926, 37122, 37123, 37125, 37285, 37288, 37289, 39234, 40597);
  script_xref(name:"RHSA", value:"2007:0939");

  script_name(english:"RHEL 4 : kernel (RHSA-2007:0939)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel is the core of the operating system.

These updated kernel packages contain fixes for the following security
issues :

* A flaw was found in the handling of process death signals. This
allowed a local user to send arbitrary signals to the suid-process
executed by that user. A successful exploitation of this flaw depends
on the structure of the suid-program and its signal handling.
(CVE-2007-3848, Important)

* A flaw was found in the CIFS file system. This could cause the umask
values of a process to not be honored on CIFS file systems where UNIX
extensions are supported. (CVE-2007-3740, Important)

* A flaw was found in the VFAT compat ioctl handling on 64-bit
systems. This allowed a local user to corrupt a kernel_dirent struct
and cause a denial of service. (CVE-2007-2878, Important)

* A flaw was found in the Advanced Linux Sound Architecture (ALSA). A
local user who had the ability to read the /proc/driver/snd-page-alloc
file could see portions of kernel memory. (CVE-2007-4571, Moderate)

* A flaw was found in the aacraid SCSI driver. This allowed a local
user to make ioctl calls to the driver that should be restricted to
privileged users. (CVE-2007-4308, Moderate)

* A flaw was found in the stack expansion when using the hugetlb
kernel on PowerPC systems. This allowed a local user to cause a denial
of service. (CVE-2007-3739, Moderate)

* A flaw was found in the handling of zombie processes. A local user
could create processes that would not be properly reaped which could
lead to a denial of service. (CVE-2006-6921, Moderate)

* A flaw was found in the CIFS file system handling. The mount option
'sec=' did not enable integrity checking or produce an error message
if used. (CVE-2007-3843, Low)

* A flaw was found in the random number generator implementation that
allowed a local user to cause a denial of service or possibly gain
privileges. This flaw could be exploited if the root user raised the
default wakeup threshold over the size of the output pool.
(CVE-2007-3105, Low)

Additionally, the following bugs were fixed :

* A flaw was found in the kernel netpoll code, creating a potential
deadlock condition. If the xmit_lock for a given network interface is
held, and a subsequent netpoll event is generated from within the lock
owning context (a console message for example), deadlock on that cpu
will result, because the netpoll code will attempt to re-acquire the
xmit_lock. The fix is to, in the netpoll code, only attempt to take
the lock, and fail if it is already acquired (rather than block on
it), and queue the message to be sent for later delivery. Any user of
netpoll code in the kernel (netdump or netconsole services), is
exposed to this problem, and should resolve the issue by upgrading to
this kernel release immediately.

* A flaw was found where, under 64-bit mode (x86_64), AMD processors
were not able to address greater than a 40-bit physical address space;
and Intel processors were only able to address up to a 36-bit physical
address space. The fix is to increase the physical addressing for an
AMD processor to 48 bits, and an Intel processor to 38 bits. Please
see the Red Hat Knowledgebase for more detailed information.

* A flaw was found in the xenU kernel that may prevent a
paravirtualized guest with more than one CPU from starting when
running under an Enterprise Linux 5.1 hypervisor. The fix is to allow
your Enterprise Linux 4 Xen SMP guests to boot under a 5.1 hypervisor.
Please see the Red Hat Knowledgebase for more detailed information.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-6921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2878.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3740.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/FAQ_42_11697.shtm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0939.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0939";
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
  if (rpm_check(release:"RHEL4", reference:"kernel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", reference:"kernel-doc-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-smp-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-55.0.12.EL")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-55.0.12.EL")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
  }
}
