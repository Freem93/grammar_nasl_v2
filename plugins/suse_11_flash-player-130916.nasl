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
  script_id(69969);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/11/17 03:37:30 $");

  script_cve_id("CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363", "CVE-2013-5324");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : flash-player (SAT Patch Numbers 8330 / 8331)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe flash-player has been updated to version 11.2.202.310
(ABSP13-21) which fixes several bugs and security issues. (SUSE
bnc#839897)

These updates resolve memory corruption vulnerabilities that could
have lead to code execution. (CVE-2013-3361 / CVE-2013-3362 /
CVE-2013-3363 / CVE-2013-5324)

Official advisory can be found on

https://www.adobe.com/support/security/bulletins/apsb13-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3362.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3363.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-5324.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8330 / 8331 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/19");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-gnome-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-kde4-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-gnome-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-kde4-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-gnome-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-kde4-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-gnome-11.2.202.310-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-kde4-11.2.202.310-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
