#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# actually a security fix.
#
# Disabled on 2013/12/05.
#

include("compat.inc");

if (description)
{
  script_id(57135);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/12/05 15:37:27 $");

  script_name(english:"SuSE 11.1 Security Update : update-test-security (2011-11-18) (deprecated)");
  script_summary(english:"Check for the update-test-security package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:"This is a fake security update for testing purposes."
  );
  script_set_attribute(
    attribute: "see_also",
    value: "https://bugzilla.novell.com/show_bug.cgi?id=64937"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the update-test-security security patch by using 'yast', for example."
  );
  script_set_attribute(attribute: "risk_factor", value: "High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:update-test-security");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/12");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not actually a security update.");


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;

if ( rpm_check( reference:"update-test-security-2-2.6.1", release:"SLES11", sp: 2, cpu:"noarch") ) flag ++;
if ( rpm_check( reference:"update-test-security-2-2.6.1", release:"SLES11", sp: 2, cpu:"noarch") ) flag ++;
if ( rpm_check( reference:"update-test-security-2-2.6.4", release:"SLES11", sp: 2, cpu:"noarch") ) flag ++;
if ( rpm_check( reference:"update-test-security-2-2.6.1", release:"SLED11", sp: 2, cpu:"noarch") ) flag ++;
if ( rpm_check( reference:"update-test-security-2-2.6.1", release:"SLED11", sp: 2, cpu:"noarch") ) flag ++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
