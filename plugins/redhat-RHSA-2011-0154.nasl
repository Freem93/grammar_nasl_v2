#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0154. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51563);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2010-4267");
  script_osvdb_id(70498);
  script_xref(name:"RHSA", value:"2011:0154");

  script_name(english:"RHEL 5 / 6 : hplip (RHSA-2011:0154)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard printers and multifunction peripherals, and tools
for installing, using, and configuring them.

A flaw was found in the way certain HPLIP tools discovered devices
using the SNMP protocol. If a user ran certain HPLIP tools that search
for supported devices using SNMP, and a malicious user is able to send
specially crafted SNMP responses, it could cause those HPLIP tools to
crash or, possibly, execute arbitrary code with the privileges of the
user running them. (CVE-2010-4267)

Red Hat would like to thank Sebastian Krahmer of the SuSE Security
Team for reporting this issue.

Users of hplip should upgrade to these updated packages, which contain
a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4267.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0154.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0154";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hpijs-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hpijs-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hpijs3-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hpijs3-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-common-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-common-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-gui-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-gui-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-libs-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-libs-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libsane-hpaio-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libsane-hpaio-1.6.7-6.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libsane-hpaio3-3.9.8-11.el5_6.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libsane-hpaio3-3.9.8-11.el5_6.1")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hpijs-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hpijs-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-common-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-common-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-debuginfo-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-debuginfo-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-gui-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-gui-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-libs-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-libs-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libsane-hpaio-3.9.8-33.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsane-hpaio-3.9.8-33.el6_0.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hpijs3 / hplip / hplip-common / hplip-debuginfo / hplip-gui / etc");
  }
}
