#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51752);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2010-3699", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-4160", "CVE-2010-4258");

  script_name(english:"SuSE 10 Security Update : the Linux kernel (ZYPP Patch Number 7303)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP3 kernel fixes
several security issues and bugs.

The following security issues were fixed :

  - A local attacker could use a Oops (kernel crash) caused
    by other flaws to write a 0 byte to a attacker
    controlled address in the kernel. This could lead to
    privilege escalation together with other issues.
    (CVE-2010-4258)

  - The backend driver in Xen 3.x allows guest OS users to
    cause a denial of service via a kernel thread leak,
    which prevents the device and guest OS from being shut
    down or create a zombie domain, causes a hang in
    zenwatch, or prevents unspecified xm commands from
    working properly, related to (1) netback, (2) blkback,
    or (3) blktap. (CVE-2010-3699)

  - The econet_sendmsg function in net/econet/af_econet.c in
    the Linux kernel, when an econet address is configured,
    allowed local users to cause a denial of service (NULL
    pointer dereference and OOPS) via a sendmsg call that
    specifies a NULL value for the remote address field.
    (CVE-2010-3849)

  - Stack-based buffer overflow in the econet_sendmsg
    function in net/econet/af_econet.c in the Linux kernel
    when an econet address is configured, allowed local
    users to gain privileges by providing a large number of
    iovec structures. (CVE-2010-3848)

  - The ec_dev_ioctl function in net/econet/af_econet.c in
    the Linux kernel did not require the CAP_NET_ADMIN
    capability, which allowed local users to bypass intended
    access restrictions and configure econet addresses via
    an SIOCSIFADDR ioctl call. (CVE-2010-3850)

  - A overflow in sendto() and recvfrom() routines was fixed
    that could be used by local attackers to potentially
    crash the kernel using some socket families like L2TP.
    (CVE-2010-4160)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3699.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4258.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7303.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-default-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-source-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.76.8")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.76.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
