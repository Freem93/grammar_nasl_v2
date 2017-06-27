#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1694. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85717);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-4491");
  script_osvdb_id(126022);
  script_xref(name:"RHSA", value:"2015:1694");

  script_name(english:"RHEL 6 / 7 : gdk-pixbuf2 (RHSA-2015:1694)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

gdk-pixbuf is an image loading library that can be extended by
loadable modules for new image formats. It is used by toolkits such as
GTK+ or clutter.

An integer overflow, leading to a heap-based buffer overflow, was
found in the way gdk-pixbuf, an image loading library for GNOME,
scaled certain bitmap format images. An attacker could use a specially
crafted BMP image file that, when processed by an application compiled
against the gdk-pixbuf library, would cause that application to crash
or execute arbitrary code with the permissions of the user running the
application. (CVE-2015-4491)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Gustavo Grieco as the original reporter.

All gdk-pixbuf2 users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2015/mfsa2015-88.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1694.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gdk-pixbuf2, gdk-pixbuf2-debuginfo and / or
gdk-pixbuf2-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2015:1694";
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
  if (rpm_check(release:"RHEL6", reference:"gdk-pixbuf2-2.24.1-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gdk-pixbuf2-debuginfo-2.24.1-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"gdk-pixbuf2-devel-2.24.1-6.el6_7")) flag++;


  if (rpm_check(release:"RHEL7", reference:"gdk-pixbuf2-2.28.2-5.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gdk-pixbuf2-debuginfo-2.28.2-5.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"gdk-pixbuf2-devel-2.28.2-5.el7_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf2 / gdk-pixbuf2-debuginfo / gdk-pixbuf2-devel");
  }
}
