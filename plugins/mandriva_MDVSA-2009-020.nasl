#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:020. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36846);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id(
    "CVE-2008-3231",
    "CVE-2008-5233",
    "CVE-2008-5234",
    "CVE-2008-5236",
    "CVE-2008-5237",
    "CVE-2008-5239",
    "CVE-2008-5240",
    "CVE-2008-5241",
    "CVE-2008-5243",
    "CVE-2008-5245",
    "CVE-2008-5246"
  );
  script_bugtraq_id(
    30698,
    30699,
    30797
  );
  script_osvdb_id(
    47158,
    47679,
    47741,
    47743,
    47745,
    47746,
    47748,
    47749,
    47750,
    47751,
    50909,
    50910,
    52938,
    52939,
    52940,
    52941,
    52942,
    52943
  );
  script_xref(name:"MDVSA", value:"2009:020");

  script_name(english:"Mandriva Linux Security Advisory : xine-lib (MDVSA-2009:020)");
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
"Failure on Ogg files manipulation can lead remote attackers to cause a
denial of service by using crafted files (CVE-2008-3231).

Failure on manipulation of either MNG or Real or MOD files can lead
remote attackers to cause a denial of service by using crafted files
(CVE: CVE-2008-5233).

Heap-based overflow allows remote attackers to execute arbitrary code
by using Quicktime media files holding crafted metadata
(CVE-2008-5234).

Heap-based overflow allows remote attackers to execute arbitrary code
by using either crafted Matroska or Real media files (CVE-2008-5236).

Failure on manipulation of either MNG or Quicktime files can lead
remote attackers to cause a denial of service by using crafted files
(CVE-2008-5237).

Multiple heap-based overflow on input plugins (http, net, smb, dvd,
dvb, rtsp, rtp, pvr, pnm, file, gnome_vfs, mms) allow attackers to
execute arbitrary code by handling that input channels. Further this
problem can even lead attackers to cause denial of service
(CVE-2008-5239).

Heap-based overflow allows attackers to execute arbitrary code by
using crafted Matroska media files (MATROSKA_ID_TR_CODECPRIVATE track
entry element). Further a failure on handling of Real media files
(CONT_TAG header) can lead to a denial of service attack
(CVE-2008-5240).

Integer underflow allows remote attackers to cause denial of service
by using Quicktime media files (CVE-2008-5241).

Failure on manipulation of Real media files can lead remote attackers
to cause a denial of service by indexing an allocated buffer with a
certain input value in a crafted file (CVE-2008-5243).

Vulnerabilities of unknown impact - possibly buffer overflow - caused
by a condition of video frame preallocation before ascertaining the
required length in V4L video input plugin (CVE-2008-5245).

Heap-based overflow allows remote attackers to execute arbitrary code
by using crafted media files. This vulnerability is in the
manipulation of ID3 audio file data tagging mainly used in MP3 file
formats (CVE-2008-5246).

This update provides the fix for all these security issues found in
xine-lib 1.1.11 of Mandriva 2008.1. The vulnerabilities:
CVE-2008-5234, CVE-2008-5236, CVE-2008-5237, CVE-2008-5239,
CVE-2008-5240, CVE-2008-5243 are found in xine-lib 1.1.15 of Mandriva
2009.0 and are also fixed by this update."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-caca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-dxr3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-smb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-wavpack");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64xine-devel-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64xine1-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libxine-devel-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libxine1-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-aa-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-caca-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-dxr3-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-esd-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-flac-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-gnomevfs-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-image-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-jack-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-plugins-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-pulse-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-sdl-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-smb-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"xine-wavpack-1.1.11.1-4.3mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xine-devel-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64xine1-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxine-devel-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libxine1-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-aa-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-caca-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-dxr3-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-esd-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-flac-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-gnomevfs-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-image-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-jack-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-plugins-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-pulse-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-sdl-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-smb-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xine-wavpack-1.1.15-2.1mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
