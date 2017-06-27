#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpoppler-devel-1740.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(43616);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-0791", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3938", "CVE-2009-4035");

  script_name(english:"openSUSE Security Update : libpoppler-devel (libpoppler-devel-1740)");
  script_summary(english:"Check for the libpoppler-devel-1740 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of libpoppler3 fixes various security issues.

CVE-2009-0791: Fix multiple integer overflows in 'pdftops' filter that
could be used by attackers to execute code.

CVE-2009-3607: Integer overflow in the
create_surface_from_thumbnail_data function in glib/poppler-page.cc in
Poppler 0.x allows remote attackers to cause a denial of service
(memory corruption) or possibly execute arbitrary code via a crafted
PDF document that triggers a heap-based buffer overflow. NOTE: some of
these details are obtained from third-party information. 

CVE-2009-3608: Integer overflow in the ObjectStream::ObjectStream
function in XRef.cc in Xpdf 3.x before 3.02pl4 and Poppler before
0.12.1, as used in GPdf, kdegraphics KPDF, CUPS pdftops, and teTeX,
might allow remote attackers to execute arbitrary code via a crafted
PDF document that triggers a heap-based buffer overflow. 

CVE-2009-3938: Buffer overflow in the ABWOutputDev::endWord function
in poppler/ABWOutputDev.cc in Poppler (aka libpoppler) 0.10.6, 0.12.0,
and possibly other versions, as used by the Abiword pdftoabw utility,
allows user-assisted remote attackers to cause a denial of service and
possibly execute arbitrary code via a crafted PDF file. 

CVE-2009-4035: A indexing error in FoFiType1::parse() was fixed that
could be used by attackers to corrupt memory and potentially execute
code."
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
    attribute:"solution", 
    value:"Update the affected libpoppler-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-devel-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-glib-devel-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-glib3-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-qt2-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-qt3-devel-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-qt4-3-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler-qt4-devel-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"libpoppler3-0.8.2-1.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"poppler-tools-0.8.2-1.5") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpoppler3");
}
