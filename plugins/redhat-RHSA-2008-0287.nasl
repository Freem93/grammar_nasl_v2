#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0287. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32421);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-1767");
  script_bugtraq_id(29312);
  script_osvdb_id(45419);
  script_xref(name:"RHSA", value:"2008:0287");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : libxslt (RHSA-2008:0287)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxslt packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

libxslt is a C library, based on libxml, for parsing of XML files into
other textual formats (eg HTML, plain text and other XML
representations of the underlying data) It uses the standard XSLT
stylesheet transformation mechanism and, being written in plain ANSI
C, is designed to be simple to incorporate into other applications

Anthony de Almeida Lopes reported the libxslt library did not properly
process long 'transformation match' conditions in the XSL stylesheet
files. An attacker could create a malicious XSL file that would cause
a crash, or, possibly, execute and arbitrary code with the privileges
of the application using libxslt library to perform XSL
transformations. (CVE-2008-1767)

All users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0287.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libxslt, libxslt-devel and / or libxslt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
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
  rhsa = "RHSA-2008:0287";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxslt-1.0.15-3")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxslt-devel-1.0.15-3")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxslt-python-1.0.15-3")) flag++;


  if (rpm_check(release:"RHEL3", reference:"libxslt-1.0.33-6")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libxslt-devel-1.0.33-6")) flag++;


  if (rpm_check(release:"RHEL4", reference:"libxslt-1.1.11-1.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxslt-devel-1.1.11-1.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxslt-python-1.1.11-1.el4_6.1")) flag++;


  if (rpm_check(release:"RHEL5", reference:"libxslt-1.1.17-2.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libxslt-devel-1.1.17-2.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libxslt-python-1.1.17-2.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libxslt-python-1.1.17-2.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libxslt-python-1.1.17-2.el5_1.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt / libxslt-devel / libxslt-python");
  }
}
