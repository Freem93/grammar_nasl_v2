#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0836. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34023);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-3281");
  script_osvdb_id(47636);
  script_xref(name:"RHSA", value:"2008:0836");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : libxml2 (RHSA-2008:0836)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 26th August 2008] The original fix used in this errata caused
some applications using the libxml2 library in an unexpected way to
crash when used with updated libxml2 packages. We have updated the
packages for Red Hat Enterprise Linux 3, 4 and 5 to use a different
fix that does not break affected applications.

The libxml2 packages provide a library that allows you to manipulate
XML files. It includes support to read, modify, and write XML and HTML
files.

A denial of service flaw was found in the way libxml2 processes
certain content. If an application linked against libxml2 processes
malformed XML content, it could cause the application to stop
responding. (CVE-2008-3281)

Red Hat would like to thank Andreas Solberg for responsibly disclosing
this issue.

All users of libxml2 are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3281.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0836.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libxml2, libxml2-devel and / or libxml2-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/22");
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
  rhsa = "RHSA-2008:0836";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-2.4.19-9.ent")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-devel-2.4.19-9.ent")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"libxml2-python-2.4.19-9.ent")) flag++;


  if (rpm_check(release:"RHEL3", reference:"libxml2-2.5.10-11")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libxml2-devel-2.5.10-11")) flag++;

  if (rpm_check(release:"RHEL3", reference:"libxml2-python-2.5.10-11")) flag++;


  if (rpm_check(release:"RHEL4", reference:"libxml2-2.6.16-12.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxml2-devel-2.6.16-12.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libxml2-python-2.6.16-12.3")) flag++;


  if (rpm_check(release:"RHEL5", reference:"libxml2-2.6.26-2.1.2.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libxml2-devel-2.6.26-2.1.2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libxml2-python-2.6.26-2.1.2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libxml2-python-2.6.26-2.1.2.4")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libxml2-python-2.6.26-2.1.2.4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
