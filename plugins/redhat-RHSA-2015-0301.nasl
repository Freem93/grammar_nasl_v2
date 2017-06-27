#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0301. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81627);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-9273");
  script_osvdb_id(115209);
  script_xref(name:"RHSA", value:"2015:0301");

  script_name(english:"RHEL 7 : hivex (RHSA-2015:0301)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hivex packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hive files are undocumented binary files that Windows uses to store
the Windows Registry on disk. Hivex is a library that can read and
write to these files.

It was found that hivex attempted to read beyond its allocated buffer
when reading a hive file with a very small size or with a truncated or
improperly formatted content. An attacker able to supply a specially
crafted hive file to an application using the hivex library could
possibly use this flaw to execute arbitrary code with the privileges
of the user running that application. (CVE-2014-9273)

Red Hat would like to thank Mahmoud Al-Qudsi of NeoSmart Technologies
for reporting this issue.

The hivex package has been upgraded to upstream version 1.3.10, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1023978)

This update also fixes the following bugs :

* Due to an error in the hivex_value_data_cell_offset() function, the
hivex utility could, in some cases, print an 'Argument list is too
long' message and terminate unexpectedly when processing hive files
from the Windows Registry. This update fixes the underlying code and
hivex now processes hive files as expected. (BZ#1145056)

* A typographical error in the Win::Hivex.3pm manual page has been
corrected. (BZ#1099286)

Users of hivex are advised to upgrade to these updated packages, which
correct these issues and adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0301.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0301";
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
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"hivex-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"hivex-debuginfo-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hivex-debuginfo-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"hivex-devel-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-debuginfo / hivex-devel / ocaml-hivex / etc");
  }
}
