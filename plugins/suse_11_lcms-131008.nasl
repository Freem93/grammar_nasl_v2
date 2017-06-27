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
  script_id(71035);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/11/22 11:51:33 $");

  script_cve_id("CVE-2013-4276");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : lcms (SAT Patch Numbers 8424 / 8425)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The lcms userland utilities were updated to fix stack overflows.

  - Multiple stack-based buffer overflows in LittleCMS
    allowed remote attackers to cause a denial of service
    (crash) via a crafted (1) ICC color profile to the
    icctrans utility or (2) TIFF image to the tiffdiff
    utility. (CVE-2013-4276)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4276.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8424 / 8425 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:lcms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:liblcms1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:liblcms1-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"lcms-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"liblcms1-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"liblcms1-32bit-1.17-77.16.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
