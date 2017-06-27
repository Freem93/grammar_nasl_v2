#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55761);
  script_version ("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/05/17 11:05:45 $");

  script_name(english:"SuSE 10 Security Update : coreutils (ZYPP Patch Number 7655)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of coreutils fixes the following security issue :

  - 697897: coreutils: when running 'su -c' to execute
    commands as different user the target user could inject
    command back into the calling users terminal via the
    TIOCSTI ioctl.

This update also fixes the following non-security issues :

  - 545797: cp behavior difference in SLES9 vs SLES10

  - 557051: Date command does not show correct results
    because of Daylight Savings Time.

  - 610731: readlink mis-detects loops

  - 654529: chmod double free memory

  - 702995: Added -L and -P to the pwd binary

  - 564082: Fixed crash of 'cp' on gpfs"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7655.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:3, reference:"coreutils-5.93-22.18.23.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
