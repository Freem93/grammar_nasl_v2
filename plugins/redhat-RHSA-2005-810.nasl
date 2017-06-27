#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:810. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20237);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_osvdb_id(20840, 20841, 20842);
  script_xref(name:"RHSA", value:"2005:810");

  script_name(english:"RHEL 2.1 / 3 / 4 : gdk-pixbuf (RHSA-2005:810)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf packages that fix several security issues are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes XPM images. An
attacker could create a carefully crafted XPM file in such a way that
it could cause an application linked with gdk-pixbuf to execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3186 to this issue.

Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
processes XPM images. An attacker could create a carefully crafted XPM
file in such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code or crash when the file was opened
by a victim. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2976 to this issue.

Ludwig Nussel also discovered an infinite-loop denial of service bug
in the way gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with gdk-pixbuf to stop responding when the file
was opened by a victim. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-2975 to this issue.

Users of gdk-pixbuf are advised to upgrade to these updated packages,
which contain backported patches and are not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-810.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gdk-pixbuf, gdk-pixbuf-devel and / or
gdk-pixbuf-gnome packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:810";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gdk-pixbuf-0.22.0-12.el2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gdk-pixbuf-devel-0.22.0-12.el2.3")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gdk-pixbuf-gnome-0.22.0-12.el2.3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gdk-pixbuf-0.22.0-13.el3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"gdk-pixbuf-devel-0.22.0-13.el3.3")) flag++;
  if (rpm_check(release:"RHEL3", reference:"gdk-pixbuf-gnome-0.22.0-13.el3.3")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gdk-pixbuf-0.22.0-17.el4.3")) flag++;
  if (rpm_check(release:"RHEL4", reference:"gdk-pixbuf-devel-0.22.0-17.el4.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf / gdk-pixbuf-devel / gdk-pixbuf-gnome");
  }
}
