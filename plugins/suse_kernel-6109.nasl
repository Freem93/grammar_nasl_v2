#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41538);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2008-1294", "CVE-2009-0028", "CVE-2009-0065", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-1046");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 6109)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update for SUSE Linux Enterprise 10 Service Pack 2
fixes various bugs and several security issues.

The following security issues were fixed: CVE-2009-0675: The
skfp_ioctl function in drivers/net/skfp/skfddi.c in the Linux kernel
permits SKFP_CLR_STATS requests only when the CAP_NET_ADMIN capability
is absent, instead of when this capability is present, which allows
local users to reset the driver statistics, related to an 'inverted
logic' issue.

  - The sock_getsockopt function in net/core/sock.c in the
    Linux kernel does not initialize a certain structure
    member, which allows local users to obtain potentially
    sensitive information from kernel memory via an
    SO_BSDCOMPAT getsockopt request. (CVE-2009-0676)

  - The clone system call in the Linux kernel allows local
    users to send arbitrary signals to a parent process from
    an unprivileged child process by launching an additional
    child process with the CLONE_PARENT flag, and then
    letting this new process exit. (CVE-2009-0028)

  - The Linux kernel does not check when a user attempts to
    set RLIMIT_CPU to 0 until after the change is made,
    which allows local users to bypass intended resource
    limits. (CVE-2008-1294)

  - Buffer overflow in net/sctp/sm_statefuns.c in the Stream
    Control Transmission Protocol (sctp) implementation in
    the Linux kernel allows remote attackers to have an
    unknown impact via an FWD-TSN (aka FORWARD-TSN) chunk
    with a large stream ID. (CVE-2009-0065)

  - The console selection feature in the Linux kernel when
    the UTF-8 console is used, allows physically proximate
    attackers to cause a denial of service (memory
    corruption) by selecting a small number of 3-byte UTF-8
    characters, which triggers an an off-by-two memory
    error. It is is not clear if this can be exploited at
    all. (CVE-2009-1046)

Also a huge number of regular bugs were fixed, please see the RPM
changelog for full details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0675.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0676.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1046.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6109.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.37_f594963d")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.37_f594963d")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
