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
  script_id(64121);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/26 14:44:46 $");

  script_cve_id("CVE-2012-3524");

  script_name(english:"SuSE 11.2 Security Update : dbus-1 (SAT Patch Number 6733)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a vulnerability in the DBUS auto-launching feature
that allowed local users to execute arbitrary programs as root.
CVE-2012-3524 has been assigned to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=697105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3524.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6733.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"dbus-1-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"dbus-1-x11-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"dbus-1-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"dbus-1-x11-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dbus-1-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"dbus-1-x11-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"dbus-1-32bit-1.2.10-3.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"dbus-1-32bit-1.2.10-3.25.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
