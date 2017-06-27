#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:651. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15947);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_osvdb_id(12843);
  script_xref(name:"RHSA", value:"2004:651");

  script_name(english:"RHEL 2.1 / 3 : imlib (RHSA-2004:651)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated imlib packages that fix several integer and buffer overflows
are now available.

[Updated Dec 22, 2004] Added multilib packages to the Itanium, PPC,
AMD64/Intel EM64T, and IBM eServer zSeries architectures for Red Hat
Enterprise Linux version 3.

The imlib packages contain an image loading and rendering library.

Pavel Kankovsky discovered several heap overflow flaws that were found
in the imlib image handler. An attacker could create a carefully
crafted image file in such a way that it could cause an application
linked with imlib to execute arbitrary code when the file was opened
by a victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-1025 to this issue.

Additionally, Pavel discovered several integer overflow flaws that
were found in the imlib image handler. An attacker could create a
carefully crafted image file in such a way that it could cause an
application linked with imlib to execute arbitrary code or crash when
the file was opened by a victim. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-1026
to this issue.

Users of imlib should update to these updated packages, which contain
backported patches and are not vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-651.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected imlib, imlib-cfgeditor and / or imlib-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:imlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:imlib-cfgeditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:imlib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/07");
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
  rhsa = "RHSA-2004:651";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"imlib-1.9.13-4.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"imlib-cfgeditor-1.9.13-4.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"imlib-devel-1.9.13-4.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"imlib-1.9.13-13.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"imlib-devel-1.9.13-13.4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imlib / imlib-cfgeditor / imlib-devel");
  }
}
