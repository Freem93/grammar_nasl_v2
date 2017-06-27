#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:055. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81938);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2014-9656", "CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9666", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9672", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");
  script_xref(name:"MDVSA", value:"2015:055");

  script_name(english:"Mandriva Linux Security Advisory : freetype2 (MDVSA-2015:055)");
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
"Updated freetype2 packages fix security vulnerabilities :

The tt_sbit_decoder_load_image function in sfnt/ttsbit.c in FreeType
before 2.5.4 does not properly check for an integer overflow, which
allows remote attackers to cause a denial of service (out-of-bounds
read) or possibly have unspecified other impact via a crafted OpenType
font (CVE-2014-9656).

The tt_face_load_hdmx function in truetype/ttpload.c in FreeType
before 2.5.4 does not establish a minimum record size, which allows
remote attackers to cause a denial of service (out-of-bounds read) or
possibly have unspecified other impact via a crafted TrueType font
(CVE-2014-9657).

The tt_face_load_kern function in sfnt/ttkern.c in FreeType before
2.5.4 enforces an incorrect minimum table length, which allows remote
attackers to cause a denial of service (out-of-bounds read) or
possibly have unspecified other impact via a crafted TrueType font
(CVE-2014-9658).

The _bdf_parse_glyphs function in bdf/bdflib.c in FreeType before
2.5.4 does not properly handle a missing ENDCHAR record, which allows
remote attackers to cause a denial of service (NULL pointer
dereference) or possibly have unspecified other impact via a crafted
BDF font (CVE-2014-9660).

type42/t42parse.c in FreeType before 2.5.4 does not consider that
scanning can be incomplete without triggering an error, which allows
remote attackers to cause a denial of service (use-after-free) or
possibly have unspecified other impact via a crafted Type42 font
(CVE-2014-9661).

The tt_cmap4_validate function in sfnt/ttcmap.c in FreeType before
2.5.4 validates a certain length field before that field's value is
completely calculated, which allows remote attackers to cause a denial
of service (out-of-bounds read) or possibly have unspecified other
impact via a crafted cmap SFNT table (CVE-2014-9663).

FreeType before 2.5.4 does not check for the end of the data during
certain parsing actions, which allows remote attackers to cause a
denial of service (out-of-bounds read) or possibly have unspecified
other impact via a crafted Type42 font, related to type42/t42parse.c
and type1/t1load.c (CVE-2014-9664).

The tt_sbit_decoder_init function in sfnt/ttsbit.c in FreeType before
2.5.4 proceeds with a count-to-size association without restricting
the count value, which allows remote attackers to cause a denial of
service (integer overflow and out-of-bounds read) or possibly have
unspecified other impact via a crafted embedded bitmap
(CVE-2014-9666).

sfnt/ttload.c in FreeType before 2.5.4 proceeds with offset+length
calculations without restricting the values, which allows remote
attackers to cause a denial of service (integer overflow and
out-of-bounds read) or possibly have unspecified other impact via a
crafted SFNT table (CVE-2014-9667).

Multiple integer overflows in sfnt/ttcmap.c in FreeType before 2.5.4
allow remote attackers to cause a denial of service (out-of-bounds
read or memory corruption) or possibly have unspecified other impact
via a crafted cmap SFNT table (CVE-2014-9669).

Multiple integer signedness errors in the pcf_get_encodings function
in pcf/pcfread.c in FreeType before 2.5.4 allow remote attackers to
cause a denial of service (integer overflow, NULL pointer dereference,
and application crash) via a crafted PCF file that specifies negative
values for the first column and first row (CVE-2014-9670).

Off-by-one error in the pcf_get_properties function in pcf/pcfread.c
in FreeType before 2.5.4 allows remote attackers to cause a denial of
service (NULL pointer dereference and application crash) via a crafted
PCF file with a 0xffffffff size value that is improperly incremented
(CVE-2014-9671).

Array index error in the parse_fond function in base/ftmac.c in
FreeType before 2.5.4 allows remote attackers to cause a denial of
service (out-of-bounds read) or obtain sensitive information from
process memory via a crafted FOND resource in a Mac font file
(CVE-2014-9672).

Integer signedness error in the Mac_Read_POST_Resource function in
base/ftobjs.c in FreeType before 2.5.4 allows remote attackers to
cause a denial of service (heap-based buffer overflow) or possibly
have unspecified other impact via a crafted Mac font (CVE-2014-9673).

The Mac_Read_POST_Resource function in base/ftobjs.c in FreeType
before 2.5.4 proceeds with adding to length values without validating
the original values, which allows remote attackers to cause a denial
of service (integer overflow and heap-based buffer overflow) or
possibly have unspecified other impact via a crafted Mac font
(CVE-2014-9674).

bdf/bdflib.c in FreeType before 2.5.4 identifies property names by
only verifying that an initial substring is present, which allows
remote attackers to discover heap pointer values and bypass the ASLR
protection mechanism via a crafted BDF font (CVE-2014-9675)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0083.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:freetype2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64freetype6-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"freetype2-demos-2.4.9-2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64freetype6-2.4.9-2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64freetype6-devel-2.4.9-2.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64freetype6-static-devel-2.4.9-2.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
