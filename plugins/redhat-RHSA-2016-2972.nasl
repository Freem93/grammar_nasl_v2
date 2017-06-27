#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2972. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95983);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/10 20:46:33 $");

  script_cve_id("CVE-2016-1248");
  script_osvdb_id(147697);
  script_xref(name:"RHSA", value:"2016:2972");

  script_name(english:"RHEL 6 / 7 : vim (RHSA-2016:2972)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for vim is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Vim (Vi IMproved) is an updated and improved version of the vi editor.

Security Fix(es) :

* A vulnerability was found in vim in how certain modeline options
were treated. An attacker could craft a file that, when opened in vim
with modelines enabled, could execute arbitrary commands with
privileges of the user running vim. (CVE-2016-1248)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1248.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-2972.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2972";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-X11-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-common-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-debuginfo-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-debuginfo-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-debuginfo-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-enhanced-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-filesystem-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vim-minimal-7.4.629-5.el6_8.1")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-X11-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-X11-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-common-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-common-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-debuginfo-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-debuginfo-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-enhanced-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-enhanced-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-filesystem-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-filesystem-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"vim-minimal-7.4.160-1.el7_3.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"vim-minimal-7.4.160-1.el7_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-X11 / vim-common / vim-debuginfo / vim-enhanced / etc");
  }
}
