#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41421);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2008-4456", "CVE-2009-2446");

  script_name(english:"SuSE 11 Security Update : MySQL (SAT Patch Number 1114)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - the COM_CREATE_DB and COM_DROP_DB suffered from format
    string vulnerabilities. (CVE-2009-2446)

  - the command line client was prone to cross-site
    scripting (XSS) attacks (CVE-2008-4456)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=520608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2446.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1114.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(79, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libmysqlclient15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libmysqlclient_r15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mysql-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mysql-client-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient_r15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mysql-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mysql-client-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libmysqlclient15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libmysqlclient_r15-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-Max-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mysql-client-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.67-13.16.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.67-13.16.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
