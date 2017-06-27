#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:148. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61991);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/01 00:27:16 $");

  script_xref(name:"MDVSA", value:"2012:148");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2012:148)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in ffmpeg. This
advisory provides updated versions which resolves various security
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ffmpeg.org/security.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avfilter1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil50");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swscaler0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavfilter1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavutil50");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpostproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libswscaler0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2011", reference:"ffmpeg-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64avfilter1-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64avformats52-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64avutil50-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64ffmpeg52-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64postproc51-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64swscaler0-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libavfilter1-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libavformats52-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libavutil50-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libffmpeg-devel-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libffmpeg-static-devel-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libffmpeg52-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpostproc51-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libswscaler0-0.7.13-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
