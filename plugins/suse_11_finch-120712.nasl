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
  script_id(64130);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2012-3374");

  script_name(english:"SuSE 11.1 Security Update : pidgin, finch and libpurple (SAT Patch Number 6534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pidgin fixes a stack-based buffer overflow in the MXit
protocol which could have potentially been exploited by remote
attackers to execute arbitrary code in the context of the user running
pidgin. (CVE-2012-3374)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3374.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6534.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"finch-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpurple-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpurple-lang-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpurple-meanwhile-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpurple-tcl-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"pidgin-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"finch-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpurple-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpurple-lang-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpurple-meanwhile-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpurple-tcl-2.6.6-0.17.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"pidgin-2.6.6-0.17.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
