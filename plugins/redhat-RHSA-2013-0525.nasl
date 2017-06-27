#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0525. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64771);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2010-4531");
  script_osvdb_id(69974);
  script_xref(name:"RHSA", value:"2013:0525");

  script_name(english:"RHEL 6 : pcsc-lite (RHSA-2013:0525)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcsc-lite packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PC/SC Lite provides a Windows SCard compatible interface for
communicating with smart cards, smart card readers, and other security
tokens.

A stack-based buffer overflow flaw was found in the way pcsc-lite
decoded certain attribute values of Answer-to-Reset (ATR) messages. A
local attacker could use this flaw to execute arbitrary code with the
privileges of the user running the pcscd daemon (root, by default), by
inserting a specially crafted smart card. (CVE-2010-4531)

This update also fixes the following bugs :

* Due to an error in the init script, the chkconfig utility did not
automatically place the pcscd init script after the start of the HAL
daemon. Consequently, the pcscd service did not start automatically at
boot time. With this update, the pcscd init script has been changed to
explicitly start only after HAL is up, thus fixing this bug.
(BZ#788474, BZ#814549)

* Because the chkconfig settings and the startup files in the
/etc/rc.d/ directory were not changed during the update described in
the RHBA-2012:0990 advisory, the user had to update the chkconfig
settings manually to fix the problem. Now, the chkconfig settings and
the startup files in the /etc/rc.d/ directory are automatically
updated as expected. (BZ#834803)

* Previously, the SCardGetAttrib() function did not work properly and
always returned the 'SCARD_E_INSUFFICIENT_BUFFER' error regardless of
the actual buffer size. This update applies a patch to fix this bug
and the SCardGetAttrib() function now works as expected. (BZ#891852)

All users of pcsc-lite are advised to upgrade to these updated
packages, which fix these issues. After installing this update, the
pcscd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0525.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcsc-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcsc-lite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcsc-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcsc-lite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pcsc-lite-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0525";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pcsc-lite-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"pcsc-lite-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pcsc-lite-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pcsc-lite-debuginfo-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pcsc-lite-devel-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pcsc-lite-doc-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"pcsc-lite-doc-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pcsc-lite-doc-1.5.2-11.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"pcsc-lite-libs-1.5.2-11.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcsc-lite / pcsc-lite-debuginfo / pcsc-lite-devel / pcsc-lite-doc / etc");
  }
}
