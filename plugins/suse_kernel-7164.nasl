#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59152);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/15 16:41:30 $");

  script_cve_id("CVE-2010-2955", "CVE-2010-3078", "CVE-2010-3081", "CVE-2010-3297");

  script_name(english:"SuSE 10 Security Update : the Linux kernel (ZYPP Patch Number 7164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for the SUSE Linux Enterprise 10 SP3 kernel fixes
several critical security issues.

The following security issues were fixed :

  - Incorrect buffer handling in the biarch-compat buffer
    handling could be used by local attackers to gain root
    privileges. This problem affects foremost x86_64, or
    potentially other biarch platforms, like PowerPC and
    S390x. (CVE-2010-3081)

  - A kernel information leak via the WEXT ioctl was fixed.
    (CVE-2010-2955)

  - A kernel information leak via the XFS filesystem was
    fixed. (CVE-2010-3078)

  - A kernel information leak in the net eql code was fixed.
    (CVE-2010-3297)

Additionally a data corruption bug in s390 was fixed :

  - A race between /proc/pid/stat and fork in the S390
    kernel could lead to data corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3297.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7164.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.69.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.69.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
