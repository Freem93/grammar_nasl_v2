#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0160. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20752);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:18 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
  script_bugtraq_id(15721, 15725, 15726, 15727, 16143);
  script_osvdb_id(21462, 21463, 22233, 22234, 22235, 22236, 22821);
  script_xref(name:"RHSA", value:"2006:0160");

  script_name(english:"RHEL 2.1 / 3 / 4 : tetex (RHSA-2006:0160)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix several integer overflows are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input and creates a typesetter-independent .dvi
(DeVice Independent) file as output.

Several flaws were discovered in the teTeX PDF parsing library. An
attacker could construct a carefully crafted PDF file that could cause
teTeX to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the names
CVE-2005-3191, CVE-2005-3192, CVE-2005-3193, CVE-2005-3624,
CVE-2005-3625, CVE-2005-3626, CVE-2005-3627 and CVE-2005-3628 to these
issues.

Users of teTeX should upgrade to these updated packages, which contain
backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3193.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3624.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3626.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3627.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3628.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0160.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0160";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-afm-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-doc-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-dvilj-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-dvips-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-fonts-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-latex-1.0.7-38.5E.10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"tetex-xdvi-1.0.7-38.5E.10")) flag++;

  if (rpm_check(release:"RHEL3", reference:"tetex-1.0.7-67.9")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-afm-1.0.7-67.9")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-dvips-1.0.7-67.9")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-fonts-1.0.7-67.9")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-latex-1.0.7-67.9")) flag++;
  if (rpm_check(release:"RHEL3", reference:"tetex-xdvi-1.0.7-67.9")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-afm-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-doc-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-dvips-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-fonts-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-latex-2.0.2-22.EL4.7")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tetex-xdvi-2.0.2-22.EL4.7")) flag++;

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
