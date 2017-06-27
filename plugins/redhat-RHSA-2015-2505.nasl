#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2505. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87046);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-5273", "CVE-2015-5287", "CVE-2015-5302");
  script_osvdb_id(130609, 130745, 130746, 130747);
  script_xref(name:"RHSA", value:"2015:2505");

  script_name(english:"RHEL 7 : abrt and libreport (RHSA-2015:2505)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated abrt and libreport packages that fix three security issues are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

It was found that the ABRT debug information installer
(abrt-action-install-debuginfo-to-abrt-cache) did not use temporary
directories in a secure way. A local attacker could use the flaw to
create symbolic links and files at arbitrary locations as the abrt
user. (CVE-2015-5273)

It was discovered that the kernel-invoked coredump processor provided
by ABRT did not handle symbolic links correctly when writing core
dumps of ABRT programs to the ABRT dump directory (/var/spool/abrt). A
local attacker with write access to an ABRT problem directory could
use this flaw to escalate their privileges. (CVE-2015-5287)

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Red Hat
Enterprise Linux as they do not post data to Red Hat Bugzilla. This
feature can however be enabled, potentially impacting modified ABRT
instances.

As a precaution, Red Hat has identified bugs filed by such non-default
Red Hat Enterprise Linux users of ABRT and marked them private.

Red Hat would like to thank Philip Pettersson of Samsung for reporting
the CVE-2015-5273 and CVE-2015-5287 issues. The CVE-2015-5302 issue
was discovered by Bastien Nocera of Red Hat.

All users of abrt and libreport are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5287.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5302.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2505.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-ccpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-pstoreoops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-upload-watch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-vmcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-addon-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-console-notification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-gui-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-python-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-retrace-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:abrt-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-anaconda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-rhel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-rhel-anaconda-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-rhel-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreport-web-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
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
  rhsa = "RHSA-2015:2505";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-ccpp-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-ccpp-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-kerneloops-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-pstoreoops-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-pstoreoops-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-python-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-python-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-upload-watch-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-upload-watch-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-vmcore-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-vmcore-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-addon-xorg-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-addon-xorg-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-cli-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-cli-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-console-notification-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-console-notification-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-dbus-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-dbus-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-debuginfo-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-desktop-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-desktop-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-devel-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-gui-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-gui-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-gui-devel-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-gui-libs-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-libs-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-python-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-python-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"abrt-python-doc-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-retrace-client-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-retrace-client-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"abrt-tui-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"abrt-tui-2.1.11-35.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-anaconda-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-anaconda-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-cli-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-cli-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-compat-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-compat-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-debuginfo-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-devel-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-filesystem-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-filesystem-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-gtk-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-gtk-devel-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-newt-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-newt-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-kerneloops-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-logger-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-logger-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-mailx-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-mailx-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-reportuploader-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-rhtsupport-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-plugin-ureport-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-plugin-ureport-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-python-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-python-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-rhel-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-rhel-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"libreport-rhel-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libreport-rhel-bugzilla-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-web-2.1.11-31.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"libreport-web-devel-2.1.11-31.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / abrt-addon-ccpp / abrt-addon-kerneloops / etc");
  }
}
