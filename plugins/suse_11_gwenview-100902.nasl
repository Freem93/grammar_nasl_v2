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
  script_id(51602);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2010-2575");

  script_name(english:"SuSE 11.1 Security Update : okular (SAT Patch Number 3062)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a heap-based overflow in okular. The RLE
decompression in the TranscribePalmImageToJPEG() function can be
exploited to execute arbitrary code with user privileges by providing
a crafted PDF file. (CVE-2010-2575)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2575.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 3062.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gwenview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kcolorchooser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kdegraphics4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kgamma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kio_kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kruler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ksnapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkdcraw7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkexiv2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libkipi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libksane0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:okular");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"gwenview-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kcolorchooser-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kdegraphics4-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kgamma-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kio_kamera-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kruler-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"ksnapshot-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libkdcraw7-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libkexiv2-7-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libkipi6-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libksane0-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"okular-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"gwenview-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kcolorchooser-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kdegraphics4-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kgamma-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kio_kamera-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kruler-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"ksnapshot-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libkdcraw7-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libkexiv2-7-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libkipi6-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libksane0-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"okular-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"gwenview-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kcolorchooser-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kruler-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ksnapshot-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libkexiv2-7-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libkipi6-4.3.5-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"okular-4.3.5-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
