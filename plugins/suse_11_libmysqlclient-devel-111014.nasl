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
  script_id(57115);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");

  script_name(english:"SuSE 11.1 Security Update : MySQL (SAT Patch Number 5285)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This MySQL version update to 5.0.94 update fixes the following
security issues :

  - CVE-2010-3833: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3834: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Insufficient Information
    (CWE-noinfo)

  - CVE-2010-3835: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Numeric Errors (CWE-189)

  - CVE-2010-3836: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3837: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3838: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Other (CWE-Other)

  - CVE-2010-3839: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Design Error
    (CWE-DesignError)

  - CVE-2010-3840: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Other (CWE-Other)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=644864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=694232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3840.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5285.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libmysqlclient_r15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mysql-client");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libmysqlclient15-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libmysqlclient_r15-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mysql-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mysql-client-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libmysqlclient15-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"libmysqlclient_r15-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"mysql-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"mysql-Max-5.0.94-0.2.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"mysql-client-5.0.94-0.2.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
