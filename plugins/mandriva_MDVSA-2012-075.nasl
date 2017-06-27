#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:075. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59096);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/27 23:38:04 $");

  script_cve_id("CVE-2011-3362", "CVE-2011-3504", "CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3895", "CVE-2011-3973", "CVE-2011-3974", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579");
  script_bugtraq_id(49115, 49118, 50555, 50642, 50760, 50880, 51290);
  script_xref(name:"MDVSA", value:"2012:075");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2012:075)");
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
"Multiple vulnerabilities has been found and corrected in ffmpeg :

The Matroska format decoder in FFmpeg does not properly allocate
memory, which allows remote attackers to execute arbitrary code via a
crafted file (CVE-2011-3362, CVE-2011-3504).

cavsdec.c in libavcodec in FFmpeg allows remote attackers to cause a
denial of service (incorrect write operation and application crash)
via an invalid bitstream in a Chinese AVS video (aka CAVS) file,
related to the decode_residual_block, check_for_slice, and
cavs_decode_frame functions, a different vulnerability than
CVE-2011-3362 (CVE-2011-3973).

Integer signedness error in the decode_residual_inter function in
cavsdec.c in libavcodec in FFmpeg allows remote attackers to cause a
denial of service (incorrect write operation and application crash)
via an invalid bitstream in a Chinese AVS video (aka CAVS) file, a
different vulnerability than CVE-2011-3362 (CVE-2011-3974).

Double free vulnerability in the Theora decoder in FFmpeg allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted stream (CVE-2011-3892).

FFmpeg does not properly implement the MKV and Vorbis media handlers,
which allows remote attackers to cause a denial of service
(out-of-bounds read) via unspecified vectors (CVE-2011-3893).

Heap-based buffer overflow in the Vorbis decoder in FFmpeg allows
remote attackers to cause a denial of service or possibly have
unspecified other impact via a crafted stream (CVE-2011-3895).

An error within the QDM2 decoder (libavcodec/qdm2.c) can be exploited
to cause a buffer overflow (CVE-2011-4351).

An integer overflow error within the 'vp3_dequant()' function
(libavcodec/vp3.c) can be exploited to cause a buffer overflow
(CVE-2011-4352).

Errors within the 'av_image_fill_pointers()', the 'vp5_parse_coeff()',
and the 'vp6_parse_coeff()' functions can be exploited to trigger
out-of-bounds reads (CVE-2011-4353).

It was discovered that Libav incorrectly handled certain malformed VMD
files. If a user were tricked into opening a crafted VMD file, an
attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user
invoking the program (CVE-2011-4364).

It was discovered that Libav incorrectly handled certain malformed
SVQ1 streams. If a user were tricked into opening a crafted SVQ1
stream file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the
privileges of the user invoking the program (CVE-2011-4579).

The updated packages have been upgraded to the 0.6.5 version where
these issues has been corrected."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil50");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swscaler0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavformats52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavutil50");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpostproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libswscaler0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/15");
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
if (rpm_check(release:"MDK2010.1", reference:"ffmpeg-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avformats52-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64avutil50-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64ffmpeg52-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64postproc51-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64swscaler0-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavformats52-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libavutil50-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libffmpeg-devel-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libffmpeg-static-devel-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libffmpeg52-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpostproc51-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libswscaler0-0.6.5-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
