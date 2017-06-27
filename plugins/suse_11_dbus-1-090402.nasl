#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41382);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/10/25 23:41:52 $");

  script_cve_id("CVE-2008-4311");

  script_name(english:"SuSE 11 Security Update : dbus (SAT Patch Number 726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The dbus package used a too permissive configuration. Therefore
intended access control for some services was not applied.
(CVE-2008-4311)

The new configuration denies access by default. Some dbus services may
break due to this setting and need an updated configuration as well.

With the previous update wireless networking didn't work anymore on
some machines due to stale files in /var/run/dbus/at_console. The dbus
init script now cleans up that directory on boot."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=443307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=486267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4311.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 726.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"dbus-1-1.2.10-3.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"dbus-1-1.2.10-3.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"dbus-1-1.2.10-3.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"dbus-1-32bit-1.2.10-3.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
