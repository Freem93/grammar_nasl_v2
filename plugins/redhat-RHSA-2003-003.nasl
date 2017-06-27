#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:003. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12347);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2002-1393");
  script_xref(name:"RHSA", value:"2003:003");

  script_name(english:"RHEL 2.1 : kdelibs (RHSA-2003:003)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security issue has been found in KDE. This errata provides updates
which resolve these issues.

KDE is a graphical desktop environment for the X Window System.

KDE fails in multiple places to properly quote URLs and filenames
before passing them to a command shell. This could allow remote
attackers to execute arbitrary commands through carefully crafted
URLs, filenames, or email addresses.

Users of KDE are advised to install the updated packages which contain
backported patches to correct this issue.

Please note that for the Itanium (IA64) architecture only, this update
also fixes several other vulnerabilities. Details concerning these
vulnerabilities can be found in advisory RHSA-2002:221 and correspond
to CVE names CVE-2002-0970, CVE-2002-1151, CVE-2002-1247, and
CVE-2002-1306."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20021220-1.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-003.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdegames");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdemultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdemultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdenetwork-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdepim-cellphone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdepim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdepim-pilot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdesdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdesdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdeutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:003";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"arts-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdebase-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdebase-devel-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdegames-2.2.2-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdegraphics-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdegraphics-devel-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-devel-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-devel-2.2.2-6")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdemultimedia-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdemultimedia-devel-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdenetwork-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdenetwork-ppp-2.2.2-3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdepim-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdepim-cellphone-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdepim-devel-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdepim-pilot-2.2.2-4")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdesdk-2.2.2-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdesdk-devel-2.2.2-2")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdeutils-2.2.2-2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arts / kdebase / kdebase-devel / kdegames / kdegraphics / etc");
  }
}
