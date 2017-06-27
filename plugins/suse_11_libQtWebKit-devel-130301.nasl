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
  script_id(65567);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2012-6093", "CVE-2013-0254");

  script_name(english:"SuSE 11.2 Security Update : libqt4 (SAT Patch Number 7441)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libqt4 has been updated to fix several security issues.

  - An information disclosure via QSharedMemory was fixed
    which allowed local attackers to read information (e.g.
    bitmap content) from the attacked user. (CVE-2013-0254)

  - openssl-incompatibility-fix.diff: Fix wrong error
    reporting when using a binary incompatible version of
    openSSL. (bnc#797006, CVE-2012-6093)

  - Various compromised SSL root certificates were
    blacklisted. Also a non-security bugfix has been 
applied :

  - Add fix for qdbusviewer not matching args (bnc#784197)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0254.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7441.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libQtWebKit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libQtWebKit4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-qt3support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-qt3support-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-sql-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libqt4-x11-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:qt4-x11-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libQtWebKit4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-qt3support-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-sql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-sql-mysql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-sql-postgresql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-sql-sqlite-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-sql-unixODBC-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libqt4-x11-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libQtWebKit4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libQtWebKit4-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-qt3support-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-mysql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-mysql-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-postgresql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-postgresql-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-sqlite-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-sqlite-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-unixODBC-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-sql-unixODBC-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-x11-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libqt4-x11-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libQtWebKit4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-qt3support-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-sql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-sql-mysql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-sql-sqlite-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"libqt4-x11-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"qt4-x11-tools-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libQtWebKit4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libQtWebKit4-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-qt3support-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-qt3support-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-sql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-sql-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-sql-mysql-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-sql-sqlite-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-x11-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libqt4-x11-32bit-4.6.3-5.20.23.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"qt4-x11-tools-4.6.3-5.20.23.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
