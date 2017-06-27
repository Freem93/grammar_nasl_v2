#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1028. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27838);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:45:04 $");

  script_cve_id("CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(39541, 39542, 39543);
  script_xref(name:"RHSA", value:"2007:1028");

  script_name(english:"RHEL 2.1 / 3 : tetex (RHSA-2007:1028)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (dvi) file as output.

Alin Rad Pop discovered a flaw in the handling of PDF files. An
attacker could create a malicious PDF file that would cause TeTeX to
crash, or potentially execute arbitrary code when opened.
(CVE-2007-5393)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-1028.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2007:1028";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-afm-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-doc-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-dvilj-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-dvips-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-fonts-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-latex-1.0.7-38.5E.12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-xdvi-1.0.7-38.5E.12")) flag++;

  if (rpm_check(release:"RHEL3", reference:"tetex-1.0.7-67.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-afm-1.0.7-67.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-dvips-1.0.7-67.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-fonts-1.0.7-67.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-latex-1.0.7-67.11")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-xdvi-1.0.7-67.11")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvilj / tetex-dvips / etc");
  }
}
