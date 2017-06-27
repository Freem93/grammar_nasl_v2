#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1975. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79850);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2013-6435");
  script_bugtraq_id(71558);
  script_osvdb_id(115601);
  script_xref(name:"RHSA", value:"2014:1975");

  script_name(english:"RHEL 5 / 6 : rpm (RHSA-2014:1975)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix one security issue are now available Red
Hat Enterprise Linux 5.6 Long Life, Red Hat Enterprise Linux 5.9
Extended Update Support, Red Hat Enterprise Linux 6.2 Advanced Update
Support, and Red Hat Enterprise Linux 6.4 Extended Update Support, Red
Hat Enterprise Linux 6.5 Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The RPM Package Manager (RPM) is a powerful command line driven
package management system capable of installing, uninstalling,
verifying, querying, and updating software packages. Each software
package consists of an archive of files along with information about
the package such as its version, description, and other information.

It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic
signature only after the temporary file has been written completely.
Under certain conditions, the system interprets the unverified
temporary file contents and extracts commands from it. This could
allow an attacker to modify signed RPM files in such a way that they
would execute code chosen by the attacker during package installation.
(CVE-2013-6435)

This issue was discovered by Florian Weimer of Red Hat Product
Security.

All rpm users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. All running
applications linked against the RPM library must be restarted for this
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1975.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.6|5\.9|6\.2|6\.4|6\.5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.6 / 5.9 / 6.2 / 6.4 / 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1975";
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
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"popt-1.10.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"popt-1.10.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"popt-1.10.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"rpm-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"rpm-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"rpm-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-apidocs-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"rpm-apidocs-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"rpm-apidocs-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-apidocs-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"rpm-apidocs-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-build-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"rpm-build-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"rpm-build-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-build-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"rpm-build-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"rpm-debuginfo-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-debuginfo-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-debuginfo-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"rpm-devel-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-devel-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-devel-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", reference:"rpm-libs-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-libs-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-libs-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"rpm-python-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"rpm-python-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"rpm-python-4.4.2.3-34.el5_9")) flag++;
  if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"rpm-python-4.4.2.3-24.el5_6")) flag++;
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"rpm-python-4.4.2.3-34.el5_9")) flag++;

  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"rpm-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"rpm-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"rpm-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"rpm-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"rpm-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"rpm-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"rpm-apidocs-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", reference:"rpm-apidocs-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"rpm-apidocs-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"rpm-build-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"rpm-build-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"rpm-build-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"rpm-build-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"rpm-build-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-build-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"rpm-build-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"rpm-cron-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", reference:"rpm-cron-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"rpm-cron-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"rpm-debuginfo-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"rpm-debuginfo-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"rpm-debuginfo-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-debuginfo-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"rpm-devel-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"rpm-devel-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"rpm-devel-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-devel-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", reference:"rpm-libs-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", reference:"rpm-libs-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"i686", reference:"rpm-libs-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-libs-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"i686", reference:"rpm-python-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"rpm-python-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"s390x", reference:"rpm-python-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"rpm-python-4.8.0-38.el6_5")) flag++;
  if (rpm_check(release:"RHEL6", sp:"4", cpu:"x86_64", reference:"rpm-python-4.8.0-33.el6_4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"2", cpu:"x86_64", reference:"rpm-python-4.8.0-20.el6_2.1")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"rpm-python-4.8.0-38.el6_5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "popt / rpm / rpm-apidocs / rpm-build / rpm-cron / rpm-debuginfo / etc");
  }
}