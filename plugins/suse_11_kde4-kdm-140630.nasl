#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(76473);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/11 10:48:00 $");

  script_cve_id("CVE-2013-4132", "CVE-2013-4133");

  script_name(english:"SuSE 11.3 Security Update : kdebase4-workspace (SAT Patch Number 9467)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kdebase4-workspace update fixes two security issues :

  - NULL pointer dereference in KDM and KCheckPass.
    (CVE-2013-4132)

  - Memory leak that could lead to a denial of service.
    (CVE-2013-4133)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4132.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4133.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9467.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kde4-kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdebase4-wallpapers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdebase4-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdebase4-workspace-ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kwin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kde4-kgreeter-plugins-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdebase4-wallpapers-4.3.5-0.11.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdebase4-workspace-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdebase4-workspace-ksysguardd-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdm-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kwin-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kde4-kgreeter-plugins-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdebase4-wallpapers-4.3.5-0.11.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdebase4-workspace-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdebase4-workspace-ksysguardd-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdm-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kwin-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kde4-kgreeter-plugins-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdebase4-wallpapers-4.3.5-0.11.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdebase4-workspace-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdebase4-workspace-ksysguardd-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdm-4.3.5-0.12.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kwin-4.3.5-0.12.18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
