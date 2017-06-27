#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2006:0619 and 
# Oracle Linux Security Advisory ELSA-2006-0619 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67402);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:16:26 $");

  script_cve_id("CVE-2006-3918");
  script_bugtraq_id(19661);
  script_osvdb_id(27488);
  script_xref(name:"RHSA", value:"2006:0619");

  script_name(english:"Oracle Linux 3 / 4 : httpd (ELSA-2006-0619)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2006:0619 :

Updated Apache httpd packages that correct security issues and resolve
bugs are now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server available for free.

A bug was found in Apache where an invalid Expect header sent to the
server was returned to the user in an unescaped error message. This
could allow an attacker to perform a cross-site scripting attack if a
victim was tricked into connecting to a site and sending a carefully
crafted Expect header. (CVE-2006-3918)

While a web browser cannot be forced to send an arbitrary Expect
header by a third-party attacker, it was recently discovered that
certain versions of the Flash plugin can manipulate request headers.
If users running such versions can be persuaded to load a web page
with a malicious Flash applet, a cross-site scripting attack against
the server may be possible.

On Red Hat Enterprise Linux 3 and 4 systems, due to an unrelated issue
in the handling of malformed Expect headers, the page produced by the
cross-site scripting attack will only be returned after a timeout
expires (2-5 minutes by default) if not first canceled by the user.

Users of httpd should update to these erratum packages, which contain
a backported patch to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-March/000078.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/09");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-2.0.46-61.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-2.0.46-61.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-devel-2.0.46-61.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-devel-2.0.46-61.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_ssl-2.0.46-61.ent.0.1")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_ssl-2.0.46-61.ent.0.1")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-devel-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-devel-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-manual-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-manual-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"httpd-suexec-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"httpd-suexec-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"mod_ssl-2.0.52-28.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mod_ssl-2.0.52-28.1")) flag++;


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
