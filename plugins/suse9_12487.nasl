#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41322);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/11/29 15:23:52 $");

  script_cve_id("CVE-2009-2698");

  script_name(english:"SuSE9 Security Update : Linux kernel (YOU Patch Number 12487)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a single critical security issue in the SUSE Linux
Enterprise 9 kernel.

  - A missing check in the MSG_PROBE handling can be used to
    execute privileges to root. (CVE-2009-2698)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2698.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12487.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-bigsmp-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-debug-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-default-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-smp-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-source-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-syms-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-um-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xen-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"kernel-xenpae-2.6.5-7.319")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-install-initrd-1.0-48.33")) flag++;
if (rpm_check(release:"SUSE9", cpu:"i586", reference:"um-host-kernel-2.6.5-7.319")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
