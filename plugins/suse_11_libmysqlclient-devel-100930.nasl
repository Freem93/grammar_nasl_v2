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
  script_id(50936);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/10/25 23:46:56 $");

  script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1849", "CVE-2010-1850", "CVE-2010-3677", "CVE-2010-3678", "CVE-2010-3681", "CVE-2010-3682", "CVE-2010-3683");

  script_name(english:"SuSE 11 / 11.1 Security Update : MySQL (SAT Patch Numbers 3220 / 3243)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following bugs have been fixed :

  - local users could delete data files for tables of other
    users. (CVE-2010-1626)

  - authenticated users could gather information for tables
    they should not have access to. (CVE-2010-1849)

  - authenticated users could crash mysqld. (CVE-2010-1848)

  - authenticated users could potentially execute arbitrary
    code as the user running mysqld. (CVE-2010-1850)

  - authenticated users could crash mysqld (CVE-2010-3677 /
    CVE-2010-3678 / CVE-2010-3681 / CVE-2010-3682 /
    CVE-2010-3683)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=609551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1626.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3677.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3678.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3681.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3682.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3683.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3220 / 3243 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-Max-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libmysqlclient15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libmysqlclient_r15-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mysql-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mysql-Max-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mysql-client-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.26.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
