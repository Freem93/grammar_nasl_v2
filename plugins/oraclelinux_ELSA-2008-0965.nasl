#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0965 and 
# Oracle Linux Security Advisory ELSA-2008-0965 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67759);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2006-7234", "CVE-2008-4690");
  script_bugtraq_id(15395);
  script_osvdb_id(30535, 49479);
  script_xref(name:"RHSA", value:"2008:0965");

  script_name(english:"Oracle Linux 3 / 4 / 5 : lynx (ELSA-2008-0965)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0965 :

An updated lynx package that corrects two security issues is now
available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Lynx is a text-based Web browser.

An arbitrary command execution flaw was found in the Lynx 'lynxcgi:'
URI handler. An attacker could create a web page redirecting to a
malicious URL that could execute arbitrary code as the user running
Lynx in the non-default 'Advanced' user mode. (CVE-2008-4690)

Note: In these updated lynx packages, Lynx will always prompt users
before loading a 'lynxcgi:' URI. Additionally, the default lynx.cfg
configuration file now marks all 'lynxcgi:' URIs as untrusted by
default.

A flaw was found in a way Lynx handled '.mailcap' and '.mime.types'
configuration files. Files in the browser's current working directory
were opened before those in the user's home directory. A local
attacker, able to convince a user to run Lynx in a directory under
their control, could possibly execute arbitrary commands as the user
running Lynx. (CVE-2006-7234)

All users of Lynx are advised to upgrade to this updated package,
which contains backported patches correcting these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000776.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/16");
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
if (rpm_check(release:"EL3", cpu:"i386", reference:"lynx-2.8.5-11.3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"lynx-2.8.5-11.3")) flag++;

if (rpm_check(release:"EL4", reference:"lynx-2.8.5-18.2.el4_7.1")) flag++;

if (rpm_check(release:"EL5", reference:"lynx-2.8.5-28.1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynx");
}
