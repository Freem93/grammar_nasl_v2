#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59120);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/14 15:30:09 $");

  script_cve_id("CVE-2006-2451", "CVE-2006-2935", "CVE-2006-3626");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 1900)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - A race condition allows local users to gain root
    privileges by changing the file mode of /proc/self/
    files in a way that causes those files (for instance
    /proc/self/environ) to become setuid root. [#192688].
    (CVE-2006-3626)

  - A stack-based buffer overflow in CDROM / DVD handling
    was fixed which could be used by a physical local
    attacker to crash the kernel or execute code within
    kernel context, depending on presence of automatic DVD
    handling in the system. [#190396]. (CVE-2006-2935)

  - Due to an argument validation error in
    prctl(PR_SET_DUMPABLE) a local attacker can easily gain
    administrator (root) privileges. [#186980].
    (CVE-2006-2451)

and the following non security bugs :

  - Limit the maximum number of LUNs to 16384 [#185164]

  - LSI 1030/MPT Fusion driver hang during error recovery --
    Optionally disable QAS [#180100]

  - advance buffer pointers in h_copy_rdma() to avoid data
    corruption [#186444]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-2451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-2935.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2006-3626.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 1900.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/25");
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
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-debug-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-default-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-smp-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-source-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-syms-2.6.16.21-0.15")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"kernel-xen-2.6.16.21-0.15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
