#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41534);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/05/17 11:12:38 $");

  script_name(english:"SuSE 10 Security Update : Linux Kernel (x86) (ZYPP Patch Number 5565)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:"This kernel security update fixes lots of bugs and some"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5565.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.29")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.29")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
