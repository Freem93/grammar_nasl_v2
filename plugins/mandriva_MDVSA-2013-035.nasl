#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:035. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66049);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/01/21 11:43:23 $");

  script_cve_id("CVE-2012-2812", "CVE-2012-2813", "CVE-2012-2814", "CVE-2012-2836", "CVE-2012-2837", "CVE-2012-2840", "CVE-2012-2841");
  script_bugtraq_id(54437);
  script_xref(name:"MDVSA", value:"2013:035");

  script_name(english:"Mandriva Linux Security Advisory : libexif (MDVSA-2013:035)");
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
"Multiple vulnerabilities has been discovered and corrected in 
libexif :

A heap-based out-of-bounds array read in the exif_entry_get_value
function in libexif/exif-entry.c in libexif 0.6.20 and earlier allows
remote attackers to cause a denial of service or possibly obtain
potentially sensitive information from process memory via an image
with crafted EXIF tags (CVE-2012-2812).

A heap-based out-of-bounds array read in the
exif_convert_utf16_to_utf8 function in libexif/exif-entry.c in libexif
0.6.20 and earlier allows remote attackers to cause a denial of
service or possibly obtain potentially sensitive information from
process memory via an image with crafted EXIF tags (CVE-2012-2813).

A buffer overflow in the exif_entry_format_value function in
libexif/exif-entry.c in libexif 0.6.20 allows remote attackers to
cause a denial of service or possibly execute arbitrary code via an
image with crafted EXIF tags (CVE-2012-2814).

A heap-based out-of-bounds array read in the exif_data_load_data
function in libexif 0.6.20 and earlier allows remote attackers to
cause a denial of service or possibly obtain potentially sensitive
information from process memory via an image with crafted EXIF tags
(CVE-2012-2836).

A divide-by-zero error in the mnote_olympus_entry_get_value function
while formatting EXIF maker note tags in libexif 0.6.20 and earlier
allows remote attackers to cause a denial of service via an image with
crafted EXIF tags (CVE-2012-2837).

An off-by-one error in the exif_convert_utf16_to_utf8 function in
libexif/exif-entry.c in libexif 0.6.20 and earlier allows remote
attackers to cause a denial of service or possibly execute arbitrary
code via an image with crafted EXIF tags (CVE-2012-2840).

An integer underflow in the exif_entry_get_value function can cause a
heap overflow and potentially arbitrary code execution while
formatting an EXIF tag, if the function is called with a buffer size
parameter equal to zero or one (CVE-2012-2841).

The updated packages have been upgraded to the 0.6.21 version which is
not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/mailarchive/message.php?msg_id=29534027"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected lib64exif-devel, lib64exif12 and / or
libexif12-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64exif12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libexif12-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64exif-devel-0.6.21-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64exif12-0.6.21-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"libexif12-common-0.6.21-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
