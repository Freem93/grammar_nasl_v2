#
# (C) Tenable Network Security, Inc.
#
# This plugin has been generated automatically from SuSE 11 update
# information, and the description text is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69511);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/08/30 12:50:49 $");

  script_cve_id("CVE-2013-1861", "CVE-2013-3783", "CVE-2013-3793", "CVE-2013-3794", "CVE-2013-3795", "CVE-2013-3796", "CVE-2013-3798", "CVE-2013-3801", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3805", "CVE-2013-3806", "CVE-2013-3807", "CVE-2013-3808", "CVE-2013-3809", "CVE-2013-3810", "CVE-2013-3811", "CVE-2013-3812");

  script_name(english:"SuSE 11.3 Security Update : MySQL (SAT Patch Number 8217)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version upgrade of mysql to 5.5.32 fixes multiple security 
issues :

CVE-2013-1861 / CVE-2013-3783 / CVE-2013-3793 / CVE-2013-3794 /
CVE-2013-3795 / CVE-2013-3796 / CVE-2013-3798 / CVE-2013-3801 /
CVE-2013-3802 / CVE-2013-3804 / CVE-2013-3805 / CVE-2013-3806 /
CVE-2013-3807 / CVE-2013-3808 / CVE-2013-3809 / CVE-2013-3810 /
CVE-2013-3811 / CVE-2013-3812

Additionally, it contains numerous bug fixes and improvements. :

  - making mysqldump work with MySQL 5.0. (bnc#768832)

  - fixed log rights. (bnc#789263 and bnc#803040)

  - binlog disabled in default configuration. (bnc#791863)

  - fixed dependencies for client package. (bnc#780019)

  - minor polishing of spec/installation

  - avoiding file conflicts with mytop

  - better fix for hardcoded libdir issue

  - fix hardcoded plugin paths. (bnc#834028)

  - Use chown --no-dereference instead of chown to improve
    security. (bnc#834967)

  - Adjust to spell !includedir correctly in /etc/my.cnf
    (bnc#734436)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3793.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3794.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3795.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3801.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3802.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3804.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3811.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3812.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8217.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libmysql55client18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libmysql55client_r18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libmysqlclient15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libmysqlclient_r15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mysql-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mysql-client-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysql55client18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysql55client_r18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysqlclient15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysqlclient_r15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libmysqlclient_r15-32bit-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mysql-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mysql-client-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libmysql55client18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libmysql55client_r18-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libmysqlclient15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libmysqlclient_r15-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mysql-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mysql-client-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mysql-tools-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysql55client18-32bit-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.96-0.6.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.32-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libmysqlclient15-32bit-5.0.96-0.6.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
