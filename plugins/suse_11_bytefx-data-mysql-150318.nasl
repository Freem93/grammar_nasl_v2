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
  script_id(83330);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/11 23:42:11 $");

  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");

  script_name(english:"SuSE 11.3 Security Update : Mono (SAT Patch Number 10497)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple SSL vulnerabilities were fixed in the Mono TLS
implementation.

  - SKIP-TLS problem could be used to client
    impersonification. (CVE-2015-2318)

  - A FREAK style SSL protocol downgrade problem was fixed.
    (CVE-2015-2319)

  - The SSLv2 support was disabled. (CVE-2015-2320)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=921312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2318.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2319.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-2320.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10497.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"bytefx-data-mysql-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"ibm-data-db2-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-core-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-firebird-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-oracle-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-postgresql-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-sqlite-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-data-sybase-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-devel-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-extras-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-jscript-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-locale-extras-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-nunit-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-wcf-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-web-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mono-winforms-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"monodoc-core-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bytefx-data-mysql-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"ibm-data-db2-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-core-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-firebird-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-oracle-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-postgresql-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-sqlite-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-data-sybase-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-devel-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-extras-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-jscript-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-locale-extras-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-nunit-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-wcf-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-web-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mono-winforms-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"monodoc-core-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-core-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-data-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-data-postgresql-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-data-sqlite-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-locale-extras-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-nunit-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-web-2.6.7-0.13.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mono-winforms-2.6.7-0.13.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
