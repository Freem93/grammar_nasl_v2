#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41151);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/04/23 18:14:41 $");

  script_name(english:"SuSE9 Security Update : subdomain-parser (YOU Patch Number 11787)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following patch supports new language features in AppArmor which
have been added to improve the confinement provided to applications
executing other applications will confined by AppArmor. Two new
execute modifiers: 'P' and 'U' are provided and are flavors of the
exisiting 'p' and 'u' modifiers but indicate that the enviroment
should be stripped across the execute transition. A new permission 'm'
is required when an application executes the mmap(2) with the prot arg
PROT_EXEC.

This is a reissue of a previous update due to RPM release number
problems."
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 11787.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/21");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"subdomain-parser-1.2-42.2")) flag++;
if (rpm_check(release:"SUSE9", reference:"subdomain-parser-common-1.2-42.2")) flag++;
if (rpm_check(release:"SUSE9", reference:"subdomain-profiles-1.2_SLES9-21.2")) flag++;
if (rpm_check(release:"SUSE9", reference:"subdomain-utils-1.2-23.2")) flag++;
if (rpm_check(release:"SUSE9", reference:"yast2-subdomain-1.2-11.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
