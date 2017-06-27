#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59128);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-5500", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6282", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669", "CVE-2008-2136");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 5370)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes quite a number of security problems :

  - A remote attacker could crash the IPSec/IPv6 stack by
    sending a bad ESP packet. This requires the host to be
    able to receive such packets (default filtered by the
    firewall). (CVE-2007-6282)

  - A problem in SIT IPv6 tunnel handling could be used by
    remote attackers to immediately crash the machine.
    (CVE-2008-2136)

  - On x86_64 a denial of service attack could be used by
    local attackers to immediately panic / crash the
    machine. (CVE-2008-1615)

  - An information leakage during coredumping of root
    processes was fixed. (CVE-2007-6206)

  - Fixed a SMP ordering problem in fcntl_setlk could
    potentially allow local attackers to execute code by
    timing file locking. (CVE-2008-1669)

  - Fixed a dnotify race condition, which could be used by
    local attackers to potentially execute code.
    (CVE-2008-1375)

  - A ptrace bug could be used by local attackers to hang
    their own processes indefinitely. (CVE-2007-5500)

  - Clear the 'direction' flag before calling signal
    handlers. For specific not yet identified programs under
    specific timing conditions this could potentially have
    caused memory corruption or code execution.
    (CVE-2008-1367)

  - The isdn_ioctl function in isdn_common.c allowed local
    users to cause a denial of service via a crafted ioctl
    struct in which ioctls is not null terminated, which
    triggers a buffer overflow. (CVE-2007-6151)

Non security related changes :

OCFS2 was updated to version v1.2.9-1-r3100.

Also a huge number of bugs were fixed. Please refer to the
RPM changelog for a detailed list."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6282.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2136.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5370.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(16, 94, 119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-smp-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-debug-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-kdump-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-smp-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.16.54-0.2.8")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.16.54-0.2.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
