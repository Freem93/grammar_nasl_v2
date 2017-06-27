#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1915-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86757);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2015-1774", "CVE-2015-4551", "CVE-2015-5212", "CVE-2015-5213", "CVE-2015-5214");
  script_bugtraq_id(74338, 74457);
  script_osvdb_id(121343, 121624, 121625, 129856, 129857, 129858, 129859);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : Recommended update for LibreOffice (SUSE-SU-2015:1915-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings LibreOffice to version 5.0.2, a major version
update.

It brings lots of new features, bugfixes and also security fixes.

Features as seen on http://www.libreoffice.org/discover/new-features/

  - LibreOffice 5.0 ships an impressive number of new
    features for its spreadsheet module, Calc: complex
    formulae image cropping, new functions, more powerful
    conditional formatting, table addressing and much more.
    Calc's blend of performance and features makes it an
    enterprise-ready, heavy duty spreadsheet application
    capable of handling all kinds of workload for an
    impressive range of use cases

  - New icons, major improvements to menus and sidebar : no
    other LibreOffice version has looked that good and
    helped you be creative and get things done the right
    way. In addition, style management is now more intuitive
    thanks to the visualization of styles right in the
    interface.

  - LibreOffice 5 ships with numerous improvements to
    document import and export filters for MS Office, PDF,
    RTF, and more. You can now timestamp PDF documents
    generated with LibreOffice and enjoy enhanced document
    conversion fidelity all around.

The Pentaho Flow Reporting Engine is now added and used.

Security issues fixed :

  - CVE-2014-8146: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) before 55.1 did not properly track
    directionally isolated pieces of text, which allowed
    remote attackers to cause a denial of service
    (heap-based buffer overflow) or possibly execute
    arbitrary code via crafted text.

  - CVE-2014-8147: The resolveImplicitLevels function in
    common/ubidi.c in the Unicode Bidirectional Algorithm
    implementation in ICU4C in International Components for
    Unicode (ICU) before 55.1 used an integer data type that
    is inconsistent with a header file, which allowed remote
    attackers to cause a denial of service (incorrect malloc
    followed by invalid free) or possibly execute arbitrary
    code via crafted text.

  - CVE-2015-4551: An arbitrary file disclosure
    vulnerability in Libreoffice and Openoffice Calc and
    Writer was fixed.

  - CVE-2015-1774: The HWP filter in LibreOffice allowed
    remote attackers to cause a denial of service (crash) or
    possibly execute arbitrary code via a crafted HWP
    document, which triggered an out-of-bounds write.

  - CVE-2015-5212: A LibreOffice 'PrinterSetup Length'
    integer underflow vulnerability could be used by
    attackers supplying documents to execute code as the
    user opening the document.

  - CVE-2015-5213: A LibreOffice 'Piece Table Counter'
    invalid check design error vulnerability allowed
    attackers supplying documents to execute code as the
    user opening the document.

  - CVE-2015-5214: Multiple Vendor LibreOffice Bookmark
    Status Memory Corruption Vulnerability allowed attackers
    supplying documents to execute code as the user opening
    the document.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.libreoffice.org/discover/new-features/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/470073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/806250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/829430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/890735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5212.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5214.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151915-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd02c58f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-797=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-797=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-797=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-797=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphite2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:graphite2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hyphen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libabw-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libabw-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libabw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdr-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdr-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-0_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libe-book-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libe-book-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libe-book-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreehand-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreehand-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreehand-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgltf-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgltf-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgltf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgraphite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgraphite2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgraphite2-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhyphen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhyphen0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_10-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblangtag-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblangtag1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblangtag1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspub-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspub-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmspub-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-0_3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmwaw-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libodfgen-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libodfgen-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libodfgen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_8-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpagemaker-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpagemaker-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpagemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-voikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-voikko-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librevenge-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librevenge-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librevenge-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librevenge-stream-0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librevenge-stream-0_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvoikko-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvoikko1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvoikko1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"graphite2-debuginfo-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"graphite2-debugsource-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgraphite2-3-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgraphite2-3-debuginfo-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgraphite2-3-32bit-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgraphite2-3-debuginfo-32bit-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cmis-client-debuginfo-0.5.0-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cmis-client-debugsource-0.5.0-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"graphite2-debuginfo-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"graphite2-debugsource-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hyphen-debugsource-2.8.8-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libabw-0_1-1-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libabw-0_1-1-debuginfo-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libabw-debugsource-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcdr-0_1-1-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcdr-0_1-1-debuginfo-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcdr-debugsource-0.1.1-5.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcmis-0_5-5-0.5.0-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcmis-0_5-5-debuginfo-0.5.0-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libe-book-0_1-1-0.1.2-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libe-book-0_1-1-debuginfo-0.1.2-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libe-book-debugsource-0.1.2-4.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-0_1-1-0.1.3-3.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-0_1-1-debuginfo-0.1.3-3.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-debugsource-0.1.3-3.5")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreehand-0_1-1-0.1.1-4.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreehand-0_1-1-debuginfo-0.1.1-4.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfreehand-debugsource-0.1.1-4.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgltf-0_0-0-0.0.1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgltf-0_0-0-debuginfo-0.0.1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgltf-debugsource-0.0.1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgraphite2-3-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgraphite2-3-32bit-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgraphite2-3-debuginfo-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgraphite2-3-debuginfo-32bit-1.3.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libhyphen0-2.8.8-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libhyphen0-debuginfo-2.8.8-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-0_10-0-0.9.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-0_10-0-debuginfo-0.9.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-debugsource-0.9.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liblangtag-debugsource-0.5.7-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liblangtag1-0.5.7-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liblangtag1-debuginfo-0.5.7-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspub-0_1-1-0.1.2-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspub-0_1-1-debuginfo-0.1.2-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmspub-debugsource-0.1.2-5.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmwaw-0_3-3-0.3.6-3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmwaw-0_3-3-debuginfo-0.3.6-3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmwaw-debugsource-0.3.6-3.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libodfgen-0_1-1-0.1.4-3.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libodfgen-0_1-1-debuginfo-0.1.4-3.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libodfgen-debugsource-0.1.4-3.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-0_8-0-0.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-0_8-0-debuginfo-0.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-debugsource-0.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpagemaker-0_0-0-0.0.2-2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpagemaker-0_0-0-debuginfo-0.0.2-2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libpagemaker-debugsource-0.0.2-2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-debugsource-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-draw-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-filters-optional-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-gnome-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-impress-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-mailmerge-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-math-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-officebean-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-pyuno-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-voikko-4.1-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-voikko-debuginfo-4.1-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.0.2.2-13.14")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"librevenge-0_0-0-0.0.2-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"librevenge-0_0-0-debuginfo-0.0.2-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"librevenge-debugsource-0.0.2-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"librevenge-stream-0_0-0-0.0.2-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"librevenge-stream-0_0-0-debuginfo-0.0.2-4.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-0_1-1-0.1.3-4.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-0_1-1-debuginfo-0.1.3-4.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-debugsource-0.1.3-4.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvoikko-debugsource-3.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvoikko1-3.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvoikko1-debuginfo-3.7.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-0_4-4-0.4.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-debugsource-0.4.1-3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-dictionaries-20150827-5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for LibreOffice");
}
