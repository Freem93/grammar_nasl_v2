#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0662 and 
# Oracle Linux Security Advisory ELSA-2007-0662 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67539);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2007-3304");
  script_bugtraq_id(24215);
  script_osvdb_id(37050, 38939);
  script_xref(name:"RHSA", value:"2007:0662");

  script_name(english:"Oracle Linux 3 / 4 : httpd (ELSA-2007-0662)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0662 :

Updated Apache httpd packages that correct a security issue are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

The Apache HTTP Server did not verify that a process was an Apache
child process before sending it signals. A local attacker with the
ability to run scripts on the Apache HTTP Server could manipulate the
scoreboard and cause arbitrary processes to be terminated which could
lead to a denial of service. (CVE-2007-3304).

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct this issue. Users should restart Apache
after installing this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-July/000268.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-2.0.46-68.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-2.0.46-68.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-devel-2.0.46-68.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-devel-2.0.46-68.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_ssl-2.0.46-68.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_ssl-2.0.46-68.ent.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-devel-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-devel-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-manual-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-manual-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-suexec-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-suexec-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mod_ssl-2.0.52-32.3.ent.0.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mod_ssl-2.0.52-32.3.ent.0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
}
