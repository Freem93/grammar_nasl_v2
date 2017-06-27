#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34234);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2012/05/17 11:27:19 $");

  script_name(english:"SuSE 10 Security Update : xntp (ZYPP Patch Number 5489)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ntp daemon did not use supplied keys.

The cause of the problem is that the authentication system is
initialized after the config is parsed and that the keyfile option is
parsed only by storing the keyfile name for later use when the
authentication system is initialized. The trustedkey option is handled
by attempting to complete the trusting of the specified keys (which
are not yet loaded). So, all the trusting fails because it has nothing
to act on.

This problem is fixed with this patch."
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5489.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, reference:"xntp-4.2.0a-70.22.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xntp-4.2.0a-70.22.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"xntp-doc-4.2.0a-70.22.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
