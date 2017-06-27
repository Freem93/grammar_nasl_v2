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
  script_id(71937);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2013-6424");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : xorg-x11-server (SAT Patch Numbers 8686 / 8687)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes the following security issue with xorg-x11-server :

  - integer underflow when handling trapezoids
    (CVE-2013-6424). (bnc#853846)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6424.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8686 / 8687 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xorg-x11-Xvnc-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xorg-x11-server-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xorg-x11-server-extra-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xorg-x11-Xvnc-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xorg-x11-server-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xorg-x11-server-extra-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-Xvnc-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-server-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-server-extra-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvnc-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-server-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-server-extra-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"xorg-x11-Xvnc-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"xorg-x11-server-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"xorg-x11-server-extra-7.4-27.70.76.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-Xvnc-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-server-7.4-27.85.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-server-extra-7.4-27.85.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
