#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59144);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0007");

  script_name(english:"SuSE 10 Security Update : the debug kernel (ZYPP Patch Number 6778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various bugs and some security issues in the SUSE
Linux Enterprise 10 SP 3 kernel.

The following security issues were fixed :

  - drivers/net/e1000/e1000_main.c in the e1000 driver in
    the Linux kernel handles Ethernet frames that exceed the
    MTU by processing certain trailing payload data as if it
    were a complete frame, which allows remote attackers to
    bypass packet filters via a large packet with a crafted
    payload. (CVE-2009-4536)

  - drivers/net/e1000e/netdev.c in the e1000e driver in the
    Linux kernel does not properly check the size of an
    Ethernet frame that exceeds the MTU, which allows remote
    attackers to have an unspecified impact via crafted
    packets. (CVE-2009-4538)

  - Missing CAP_NET_ADMIN checks in the ebtables netfilter
    code might have allowed local attackers to modify bridge
    firewall settings. (CVE-2010-0007)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0007.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6778.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/15");
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
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.59.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.59.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
