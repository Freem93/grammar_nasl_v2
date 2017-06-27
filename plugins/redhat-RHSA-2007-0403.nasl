#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0403. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25476);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:35:21 $");

  script_cve_id("CVE-2007-2754");
  script_bugtraq_id(24074);
  script_osvdb_id(36509);
  script_xref(name:"RHSA", value:"2007:0403");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : freetype (RHSA-2007:0403)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix a security flaw are now available
for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeType is a free, high-quality, portable font engine.

An integer overflow flaw was found in the way the FreeType font engine
processed TTF font files. If a user loaded a carefully crafted font
file with a program linked against FreeType, it could cause the
application to crash or execute arbitrary code. While it is uncommon
for a user to explicitly load a font file, there are several
application file formats which contain embedded fonts that are parsed
by FreeType. (CVE-2007-2754)

Users of FreeType should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2754.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0403.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/22");
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
if (! ereg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0403";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"freetype-2.0.3-10.el21")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"freetype-devel-2.0.3-10.el21")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"freetype-utils-2.0.3-10.el21")) flag++;


  if (rpm_check(release:"RHEL3", reference:"freetype-2.1.4-7.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"freetype-devel-2.1.4-7.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"freetype-2.1.9-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-demos-2.1.9-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-devel-2.1.9-6.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-utils-2.1.9-6.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"freetype-2.2.1-19.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freetype-demos-2.2.1-19.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freetype-demos-2.2.1-19.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freetype-demos-2.2.1-19.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"freetype-devel-2.2.1-19.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel / freetype-utils");
  }
}
