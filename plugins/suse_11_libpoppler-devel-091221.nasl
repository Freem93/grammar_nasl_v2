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
  script_id(43620);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-0791", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3938", "CVE-2009-4035");

  script_name(english:"SuSE 11 Security Update : libpoppler (SAT Patch Number 1731)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libpoppler4 fixes various security issues.

  - Fix multiple integer overflows in 'pdftops' filter that
    could be used by attackers to execute code.
    (CVE-2009-0791)

  - Integer overflow in the
    create_surface_from_thumbnail_data function in
    glib/poppler-page.cc in Poppler 0.x allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via a
    crafted PDF document that triggers a heap-based buffer
    overflow. NOTE: some of these details are obtained from
    third-party information. (CVE-2009-3607)

  - Integer overflow in the ObjectStream::ObjectStream
    function in XRef.cc in Xpdf 3.x before 3.02pl4 and
    Poppler before 0.12.1, as used in GPdf, kdegraphics
    KPDF, CUPS pdftops, and teTeX, might allow remote
    attackers to execute arbitrary code via a crafted PDF
    document that triggers a heap-based buffer overflow.
    (CVE-2009-3608)

  - Buffer overflow in the ABWOutputDev::endWord function in
    poppler/ABWOutputDev.cc in Poppler (aka libpoppler)
    0.10.6, 0.12.0, and possibly other versions, as used by
    the Abiword pdftoabw utility, allows user-assisted
    remote attackers to cause a denial of service and
    possibly execute arbitrary code via a crafted PDF file.
    (CVE-2009-3938)

  - A indexing error in FoFiType1::parse() was fixed that
    could be used by attackers to corrupt memory and
    potentially execute code. (CVE-2009-4035)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=507102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=543090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=546393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-0791.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3607.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3938.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4035.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1731.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpoppler-glib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpoppler4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libpoppler-glib4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libpoppler-qt4-3-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libpoppler4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libpoppler-glib4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libpoppler-qt4-3-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libpoppler4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libpoppler-glib4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libpoppler-qt4-3-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libpoppler4-0.10.1-1.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"poppler-tools-0.10.1-1.31.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
