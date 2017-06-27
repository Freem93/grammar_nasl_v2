#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0280. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21362);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-1550");
  script_osvdb_id(24294);
  script_xref(name:"RHSA", value:"2006:0280");

  script_name(english:"RHEL 2.1 / 4 : dia (RHSA-2006:0280)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated Dia package that fixes several buffer overflow bugs are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Dia drawing program is designed to draw various types of diagrams.

infamous41md discovered three buffer overflow bugs in Dia's xfig file
format importer. If an attacker is able to trick a Dia user into
opening a carefully crafted xfig file, it may be possible to execute
arbitrary code as the user running Dia. (CVE-2006-1550)

Users of Dia should update to these erratum packages, which contain
backported patches and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-1550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0280.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dia package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/29");
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
if (! ereg(pattern:"^(2\.1|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0280";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"dia-0.88.1-3.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"dia-0.94-5.4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dia");
  }
}
