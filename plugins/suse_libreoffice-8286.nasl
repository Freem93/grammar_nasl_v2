#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62781);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/11/20 11:51:03 $");

  script_cve_id("CVE-2012-4233");

  script_name(english:"SuSE 10 Security Update : LibreOffice (ZYPP Patch Number 8286)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to SUSE 3.5 bugfix release 13 (based on
upstream 3.5.6-rc2) which fixes a lot of bugs.

The following bugs have been fixed :

  - polygon fill rule. (bnc#759172)

  - open XML in Writer. (bnc#777181)

  - undo in text objects (fdo#36138)

  - broken numbering level. (bnc#760019)

  - better MathML detection. (bnc#774921)

  - pictures in DOCX import. (bnc#772094)

  - collapsing border painting (fdo#39415)

  - better DOCX text box export (fdo#45724)

  - hidden text in PPTX import. (bnc#759180)

  - slide notes in PPTX import. (bnc#768027)

  - RTL paragraphs in DOC import (fdo#43398)

  - better vertical text imports. (bnc#744510)

  - HYPERLINK field in DOCX import (fdo#51034)

  - shadow color on partial redraw. (bnc#773515)

  - floating objects in DOCX import. (bnc#775899)

  - graphite2 hyphenation regression (fdo#49486)

  - missing shape position and size. (bnc#760997)

  - page style attributes in ODF import (fdo#38056)

  - browsing in Template dialog crasher (fdo#46249)

  - wrong master slide shape being used. (bnc#758565)

  - page borders regression in ODT import (fdo#38056)

  - invalidate bound rect after drag&amp;drop (fdo#44534)

  - rotated shape margins in PPTX import. (bnc#773048)

  - pasting into more than 1 sheet crasher (fdo#47311)

  - crashers in PPT/PPTX import (bnc#768027, bnc#774167

  - missing footnote in DOCX/DOC/RTF export (fdo#46020)

  - checkbox no-label behaviour (fdo#51336, bnc#757602)

  - try somewhat harder to read w:position. (bnc#773061)

  - FormatNumber can handle sal_uInt32 values (fdo#51793)

  - rectangle-paragraph tables in DOCX import. (bnc#775899)

  - header and bullet in slideshow transition. (bnc#759172)

  - default background color in DOC/DOCX export (fdo#45724)

  - font name / size attributes in DOCX import. (bnc#774681)

  - zero rect. size causing wrong line positions (fdo#47434)

  - adjusted display of Bracket/BracePair in PPT.
    (bnc#741480)

  - use Unicode functions for QuickStarter tooltip
    (fdo#52143)

  - TabRatio API and detect macro at group shape fixes.
    (bnc#770708)

  - indented text in DOCX file does not wrap correctly.
    (bnc#775906)

  - undocked toolbars do not show all icons in special ratio
    (fdo#47071)

  - cross-reference text when Caption order is Numbering
    first (fdo#50801)

  - bullet color same as following text by default.
    (bnc#719988, bnc#734733)

  - misc RTF import fixes (rhbz#819304, fdo#49666,
    bnc#774681, fdo#51772, fdo#48033, fdo#52066, fdo#48335,
    fdo#48446, fdo#49892, fdo#46966)

  - libvisio was updated to 0.0.19: o file displays as blank
    page in Draw (fdo#50990)

  - Use the vendor SUSE instead of Novell, Inc.

  - Some NULL pointer dereferences were fixed.
    (CVE-2012-4233) Security Issue refernce :

  - CVE-2012-4233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4233.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8286.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-af-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ar-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ca-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-cs-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-da-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-de-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-el-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-en-GB-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-es-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-fi-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-fr-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-galleries-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-gnome-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-gu-IN-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-hi-IN-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-hu-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-it-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ja-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-kde-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ko-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-mono-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nb-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nl-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-nn-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-pl-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-pt-BR-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-ru-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-sk-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-sv-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-xh-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zh-CN-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zh-TW-3.5.4.13-0.7.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"libreoffice-zu-3.5.4.13-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
