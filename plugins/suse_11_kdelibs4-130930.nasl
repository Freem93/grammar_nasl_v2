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
  script_id(70632);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_cve_id("CVE-2012-4512", "CVE-2012-4513", "CVE-2012-4515");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : kdelibs4 (SAT Patch Numbers 8401 / 8402)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kdelibs4 update fixes several security issues related to
khtml/konqueror.

  - Fix security issues and NULL pointer references in
    khtml/konqueror (bnc#787520) (CVE-2012-4512 /
    CVE-2012-4513 / CVE-2012-4515)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4515.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8401 / 8402 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdelibs4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kdelibs4-doc-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdelibs4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdelibs4-core-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kdelibs4-doc-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libkde4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libkdecore4-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libkde4-32bit-4.3.5-0.12.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libkdecore4-32bit-4.3.5-0.12.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
