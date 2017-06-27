#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0616. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54598);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-1091", "CVE-2011-4922");
  script_bugtraq_id(46837);
  script_osvdb_id(74921);
  script_xref(name:"RHSA", value:"2011:0616");

  script_name(english:"RHEL 6 : pidgin (RHSA-2011:0616)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix multiple security issues and various
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

Multiple NULL pointer dereference flaws were found in the way the
Pidgin Yahoo! Messenger Protocol plug-in handled malformed YMSG
packets. A remote attacker could use these flaws to crash Pidgin via a
specially crafted notification message. (CVE-2011-1091)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Marius Wachtler as the original
reporter.

This update also fixes the following bugs :

* Previous versions of the pidgin package did not properly clear
certain data structures used in libpurple/cipher.c when attempting to
free them. Partial information could potentially be extracted from the
incorrectly cleared regions of the previously freed memory. With this
update, data structures are properly cleared when freed. (BZ#684685)

* This erratum upgrades Pidgin to upstream version 2.7.9. For a list
of all changes addressed in this upgrade, refer to
http://developer.pidgin.im/wiki/ChangeLog (BZ#616917)

* Some incomplete translations for the kn_IN and ta_IN locales have
been corrected. (BZ#633860, BZ#640170)

Users of pidgin should upgrade to these updated packages, which
resolve these issues. Pidgin must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.pidgin.im/wiki/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0616.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0616";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-perl-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-perl-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-tcl-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-tcl-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-debuginfo-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-debuginfo-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-devel-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-docs-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-docs-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-perl-2.7.9-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-perl-2.7.9-3.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
  }
}
