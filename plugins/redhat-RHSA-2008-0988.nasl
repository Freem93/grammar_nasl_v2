#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0988. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34811);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-4225", "CVE-2008-4226");
  script_osvdb_id(49992, 49993);
  script_xref(name:"RHSA", value:"2008:0988");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : libxml2 (RHSA-2008:0988)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix security issues are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

libxml2 is a library for parsing and manipulating XML files. It
includes support for reading, modifying, and writing XML and HTML
files.

An integer overflow flaw causing a heap-based buffer overflow was
found in the libxml2 XML parser. If an application linked against
libxml2 processed untrusted, malformed XML content, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2008-4226)

A denial of service flaw was discovered in the libxml2 XML parser. If
an application linked against libxml2 processed untrusted, malformed
XML content, it could cause the application to enter an infinite loop.
(CVE-2008-4225)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

Users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4225.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-4226.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0988.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libxml2, libxml2-devel and / or libxml2-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0988";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-2.4.19-12.ent")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-devel-2.4.19-12.ent")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-python-2.4.19-12.ent")) flag++;


  if (rpm_check(release:"RHEL3", reference:"libxml2-2.5.10-14")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libxml2-devel-2.5.10-14")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libxml2-python-2.5.10-14")) flag++;


  if (rpm_check(release:"RHEL4", reference:"libxml2-2.6.16-12.6")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxml2-devel-2.6.16-12.6")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxml2-python-2.6.16-12.6")) flag++;


  if (rpm_check(release:"RHEL5", reference:"libxml2-2.6.26-2.1.2.7")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libxml2-devel-2.6.26-2.1.2.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libxml2-python-2.6.26-2.1.2.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libxml2-python-2.6.26-2.1.2.7")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libxml2-python-2.6.26-2.1.2.7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python");
  }
}
