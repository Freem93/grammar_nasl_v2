#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1728-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93174);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-0794", "CVE-2016-0795");
  script_osvdb_id(134627, 134628);

  script_name(english:"SUSE SLED12 Security Update : LibreOffice (SUSE-SU-2016:1728-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.1.3.2, bringing many new features
and bug fixes.

Two security issues have been fixed :

  - CVE-2016-0795: LibreOffice allowed remote attackers to
    cause a denial of service (memory corruption) or
    possibly have unspecified other impact via a crafted
    LwpTocSuperLayout record in a LotusWordPro (lwp)
    document.

  - CVE-2016-0794: The lwp filter in LibreOffice allowed
    remote attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via a crafted LotusWordPro (lwp) document.

A comprehensive list of new features and improvements in this release
is provided by the Document Foundation at
https://wiki.documentfoundation.org/ReleaseNotes/5.1 .

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/718113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/856729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.documentfoundation.org/ReleaseNotes/5.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0795.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161728-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?caff185b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-1016=1

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-1016=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-1016=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-1016=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-1016=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-1016=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cmis-client-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hunspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hunspell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hunspell-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hunspell-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hunspell-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:hyphen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libOpenCOLLADA0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libOpenCOLLADA0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_atomic1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_atomic1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_date_time1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_date_time1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_filesystem1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_filesystem1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_iostreams1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_iostreams1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_program_options1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_program_options1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_regex1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_regex1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_signals1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_signals1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_system1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_system1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_thread1_54_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libboost_thread1_54_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-0_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcmis-0_5-5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libetonyek-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhyphen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhyphen0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-0_11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libixion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-0_11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liborcus-debugsource");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-0_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-0_1-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvisio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-0_4-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-dictionaries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:myspell-lightproof-ru_RU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openCOLLADA-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"cmis-client-debuginfo-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"cmis-client-debugsource-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-32bit-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-debuginfo-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-debuginfo-32bit-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-debugsource-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-tools-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hunspell-tools-debuginfo-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"hyphen-debugsource-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libOpenCOLLADA0-1_3335ac1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libOpenCOLLADA0-debuginfo-1_3335ac1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_atomic1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_atomic1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_date_time1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_date_time1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_filesystem1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_filesystem1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_iostreams1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_iostreams1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_program_options1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_program_options1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_regex1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_regex1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_signals1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_signals1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_system1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_system1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_thread1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libboost_thread1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libcmis-0_5-5-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libcmis-0_5-5-debuginfo-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libetonyek-0_1-1-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libetonyek-0_1-1-debuginfo-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libetonyek-debugsource-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libhyphen0-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libhyphen0-debuginfo-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libixion-0_11-0-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libixion-0_11-0-debuginfo-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libixion-debugsource-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"liborcus-0_11-0-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"liborcus-0_11-0-debuginfo-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"liborcus-debugsource-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-debugsource-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-draw-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-filters-optional-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-gnome-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-impress-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-mailmerge-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-math-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-officebean-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-pyuno-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvisio-0_1-1-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvisio-0_1-1-debuginfo-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libvisio-debugsource-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwps-0_4-4-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libwps-debugsource-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"myspell-dictionaries-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"myspell-lightproof-en-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"openCOLLADA-debugsource-1_3335ac1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cmis-client-debuginfo-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cmis-client-debugsource-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-32bit-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-debuginfo-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-debuginfo-32bit-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-debugsource-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-tools-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hunspell-tools-debuginfo-1.3.2-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"hyphen-debugsource-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libOpenCOLLADA0-1_3335ac1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libOpenCOLLADA0-debuginfo-1_3335ac1-2.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_atomic1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_atomic1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_date_time1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_date_time1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_filesystem1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_filesystem1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_iostreams1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_iostreams1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_program_options1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_program_options1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_regex1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_regex1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_signals1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_signals1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_system1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_system1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_thread1_54_0-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libboost_thread1_54_0-debuginfo-1.54.0-15.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcmis-0_5-5-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcmis-0_5-5-debuginfo-0.5.1-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-0_1-1-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-0_1-1-debuginfo-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libetonyek-debugsource-0.1.6-6.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libhyphen0-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libhyphen0-debuginfo-2.8.8-12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-0_11-0-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-0_11-0-debuginfo-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libixion-debugsource-0.11.0-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-0_11-0-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-0_11-0-debuginfo-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liborcus-debugsource-0.11.0-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-debugsource-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-draw-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-filters-optional-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-gnome-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-impress-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-mailmerge-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-math-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-officebean-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-pyuno-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.1.3.2-22.9")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-0_1-1-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-0_1-1-debuginfo-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libvisio-debugsource-0.1.5-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-0_4-4-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-0_4-4-debuginfo-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwps-debugsource-0.4.2-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-dictionaries-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-lightproof-en-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-lightproof-hu_HU-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-lightproof-pt_BR-20160511-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"myspell-lightproof-ru_RU-20160511-11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibreOffice");
}
