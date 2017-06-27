#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0966 and 
# Oracle Linux Security Advisory ELSA-2007-0966 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67586);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 16:53:46 $");

  script_cve_id("CVE-2007-5116");
  script_bugtraq_id(26350);
  script_osvdb_id(40409);
  script_xref(name:"RHSA", value:"2007:0966");

  script_name(english:"Oracle Linux 3 / 4 / 5 : perl (ELSA-2007-0966)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0966 :

Updated Perl packages that fix a security issue are now available for
Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

A flaw was found in Perl's regular expression engine. Specially
crafted input to a regular expression can cause Perl to improperly
allocate memory, possibly resulting in arbitrary code running with the
permissions of the user running Perl. (CVE-2007-5116)

Users of Perl are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue.

Red Hat would like to thank Tavis Ormandy and Will Drewry for properly
disclosing this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000379.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000380.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"perl-5.8.0-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"perl-5.8.0-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"perl-CGI-2.89-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"perl-CGI-2.89-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"perl-CPAN-1.61-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"perl-CPAN-1.61-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"perl-DB_File-1.806-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"perl-DB_File-1.806-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"perl-suidperl-5.8.0-97.EL3.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"perl-suidperl-5.8.0-97.EL3.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"perl-5.8.5-36.el4_5.2.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"perl-5.8.5-36.el4_5.2.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"perl-suidperl-5.8.5-36.el4_5.2.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"perl-suidperl-5.8.5-36.el4_5.2.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"perl-5.8.8-10.0.1.el5_0.2")) flag++;
if (rpm_check(release:"EL5", reference:"perl-suidperl-5.8.8-10.0.1.el5_0.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CGI / perl-CPAN / perl-DB_File / perl-suidperl");
}
