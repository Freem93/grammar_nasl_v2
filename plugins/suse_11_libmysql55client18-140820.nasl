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
  script_id(77435);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/10/17 17:39:52 $");

  script_cve_id("CVE-2014-2484", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4214", "CVE-2014-4233", "CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260");

  script_name(english:"SuSE 11.3 Security Update : MySQL (SAT Patch Number 9624)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This MySQL update provides the following :

  - upgrade to version 5.5.39, [bnc#887580]

  - CVE's fixed: (CVE-2014-2484 / CVE-2014-4258 /
    CVE-2014-4260 / CVE-2014-2494 / CVE-2014-4238 /
    CVE-2014-4207 / CVE-2014-4233 / CVE-2014-4240 /
    CVE-2014-4214 / CVE-2014-4243) See also:
    http://www.oracle.com/technetwork/topics/security/cpujul
    2014-1972956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4233.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4240.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4260.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9624.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysql55client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysql55client18-5.5.39-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysql55client18-32bit-5.5.39-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysql55client_r18-5.5.39-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysqlclient15-5.0.96-0.6.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysqlclient15-32bit-5.0.96-0.6.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libmysqlclient_r15-5.0.96-0.6.13")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mysql-5.5.39-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mysql-client-5.5.39-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mysql-tools-5.5.39-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
