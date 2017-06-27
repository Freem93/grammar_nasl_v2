#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0395 and 
# Oracle Linux Security Advisory ELSA-2007-0395 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67508);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2007-1349");
  script_bugtraq_id(23192);
  script_osvdb_id(34540, 34541);
  script_xref(name:"RHSA", value:"2007:0395");

  script_name(english:"Oracle Linux 3 / 4 / 5 : mod_perl (ELSA-2007-0395)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0395 :

Updated mod_perl packages that fix a security issue are now available
for Red Hat Enterprise Linux 3, 4, 5.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Mod_perl incorporates a Perl interpreter into the Apache web server,
so that the Apache web server can directly execute Perl code.

An issue was found in the 'namespace_from_uri' method of the
ModPerl::RegistryCooker class. If a server implemented a mod_perl
registry module using this method, a remote attacker requesting a
carefully crafted URI can cause resource consumption, which could lead
to a denial of service (CVE-2007-1349).

Users of mod_perl should update to these erratum packages which
contain a backported fix to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000223.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_perl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_perl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_perl-1.99_09-12.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_perl-1.99_09-12.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_perl-devel-1.99_09-12.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_perl-devel-1.99_09-12.ent")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"mod_perl-1.99_16-4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mod_perl-1.99_16-4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mod_perl-devel-1.99_16-4.5")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mod_perl-devel-1.99_16-4.5")) flag++;

if (rpm_check(release:"EL5", reference:"mod_perl-2.0.2-6.3.el5")) flag++;
if (rpm_check(release:"EL5", reference:"mod_perl-devel-2.0.2-6.3.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_perl / mod_perl-devel");
}
