#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:414. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14326);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/28 17:44:45 $");

  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_osvdb_id(9026, 9035, 9036);
  script_xref(name:"RHSA", value:"2004:414");

  script_name(english:"RHEL 2.1 / 3 : qt (RHSA-2004:414)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qt packages that fix security issues in several of the image
decoders are now available.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

During a security audit, Chris Evans discovered a heap overflow in the
BMP image decoder in Qt versions prior to 3.3.3. An attacker could
create a carefully crafted BMP file in such a way that it would cause
an application linked with Qt to crash or possibly execute arbitrary
code when the file was opened by a victim. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2004-0691 to this issue.

Additionally, various flaws were discovered in the GIF, XPM, and JPEG
decoders in Qt versions prior to 3.3.3. An attacker could create
carefully crafted image files in such a way that it could cause an
application linked against Qt to crash when the file was opened by a
victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the names CVE-2004-0692 and CVE-2004-0693
to these issues.

Users of Qt should update to these updated packages which contain
backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0693.html"
  );
  # http://www.trolltech.com/developer/changes/changes-3.3.3.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9aaee330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-414.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-Xt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:414";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"qt-2.3.1-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"qt-Xt-2.3.1-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"qt-designer-2.3.1-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"qt-devel-2.3.1-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"qt-static-2.3.1-10")) flag++;

  if (rpm_check(release:"RHEL3", reference:"qt-3.1.2-13.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"qt-MySQL-3.1.2-13.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"qt-config-3.1.2-13.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"qt-designer-3.1.2-13.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"qt-devel-3.1.2-13.4")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt / qt-MySQL / qt-Xt / qt-config / qt-designer / qt-devel / etc");
  }
}
