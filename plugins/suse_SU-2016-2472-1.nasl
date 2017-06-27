#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2472-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93910);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/03/06 15:01:21 $");

  script_cve_id("CVE-2016-4324");
  script_osvdb_id(140635);

  script_name(english:"SUSE SLED12 Security Update : libreoffice (SUSE-SU-2016:2472-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LibreOffice was updated to version 5.1.5.2, bringing enhancements and
bug fixes.

  - CVE-2016-4324: Parsing the Rich Text Format character
    style index was insufficiently checked for validity.
    Documents could be constructed which dereference an
    iterator to the first entry of an empty STL container.
    (bsc#987553)

  - Don't use 'nullable' for introspection, as it isn't
    available on SLE 12's version of gobject-introspection.
    This prevents a segmentation fault in gnome-documents.
    (bsc#1000102)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4324.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162472-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?026e5f23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1:zypper in -t patch
SUSE-SLE-WE-12-SP1-2016-1442=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1442=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-calc-extensions-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-debugsource-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-draw-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-filters-optional-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-gnome-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-impress-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-mailmerge-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-math-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-math-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-officebean-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-pyuno-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-5.1.5.2-29.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libreoffice-writer-extensions-5.1.5.2-29.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
