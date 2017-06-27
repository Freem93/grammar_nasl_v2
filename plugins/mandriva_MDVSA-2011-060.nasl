#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:060. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(53272);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4639", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-4704", "CVE-2011-2162");
  script_xref(name:"MDVSA", value:"2011:060");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2011:060)");
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
"Multiple vulnerabilities has been identified and fixed in ffmpeg :

oggparsevorbis.c in FFmpeg 0.5 does not properly perform certain
pointer arithmetic, which might allow remote attackers to obtain
sensitive memory contents and cause a denial of service via a crafted
file that triggers an out-of-bounds read. (CVE-2009-4632)

vorbis_dec.c in FFmpeg 0.5 uses an assignment operator when a
comparison operator was intended, which might allow remote attackers
to cause a denial of service and possibly execute arbitrary code via a
crafted file that modifies a loop counter and triggers a heap-based
buffer overflow. (CVE-2009-4633)

Multiple integer underflows in FFmpeg 0.5 allow remote attackers to
cause a denial of service and possibly execute arbitrary code via a
crafted file that (1) bypasses a validation check in vorbis_dec.c and
triggers a wraparound of the stack pointer, or (2) access a pointer
from out-of-bounds memory in mov.c, related to an elst tag that
appears before a tag that creates a stream. (CVE-2009-4634)

FFmpeg 0.5 allows remote attackers to cause a denial of service and
possibly execute arbitrary code via a crafted MOV container with
improperly ordered tags that cause (1) mov.c and (2) utils.c to use
inconsistent codec types and identifiers, which causes the mp3 decoder
to process a pointer for a video structure, leading to a stack-based
buffer overflow. (CVE-2009-4635)

The av_rescale_rnd function in the AVI demuxer in FFmpeg 0.5 allows
remote attackers to cause a denial of service (crash) via a crafted
AVI file that triggers a divide-by-zero error. (CVE-2009-4639)

Array index error in vorbis_dec.c in FFmpeg 0.5 allows remote
attackers to cause a denial of service and possibly execute arbitrary
code via a crafted Vorbis file that triggers an out-of-bounds read.
(CVE-2009-4640)

flicvideo.c in libavcodec 0.6 and earlier in FFmpeg, as used in
MPlayer and other products, allows remote attackers to execute
arbitrary code via a crafted flic file, related to an arbitrary offset
dereference vulnerability. (CVE-2010-3429)

libavcodec/vorbis_dec.c in the Vorbis decoder in FFmpeg 0.6.1 and
earlier allows remote attackers to cause a denial of service
(application crash) via a crafted .ogg file, related to the
vorbis_floor0_decode function. (CVE-2010-4704)

And several additional vulnerabilities originally discovered by Google
Chrome developers were also fixed with this advisory.

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swscaler0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libswscaler0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"ffmpeg-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avformats52-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64avutil49-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64ffmpeg51-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64swscaler0-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavformats52-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libavutil49-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libffmpeg-devel-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libffmpeg-static-devel-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libffmpeg51-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libswscaler0-0.4.9-3.pre1.14161.1.4mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
