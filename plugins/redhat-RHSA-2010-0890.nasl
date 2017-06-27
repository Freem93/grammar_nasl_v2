#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0890. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50643);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-3711");
  script_bugtraq_id(44283);
  script_xref(name:"RHSA", value:"2010:0890");

  script_name(english:"RHEL 6 : pidgin (RHSA-2010:0890)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

Multiple NULL pointer dereference flaws were found in the way Pidgin
handled Base64 decoding. A remote attacker could use these flaws to
crash Pidgin if the target Pidgin user was using the Yahoo! Messenger
Protocol, MSN, MySpace, or Extensible Messaging and Presence Protocol
(XMPP) protocol plug-ins, or using the Microsoft NT LAN Manager (NTLM)
protocol for authentication. (CVE-2010-3711)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Daniel Atallah as the original reporter.

All Pidgin users should upgrade to these updated packages, which
contain a backported patch to resolve these issues. Pidgin must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3711.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0890.html"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2010:0890";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-perl-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-perl-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-tcl-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-tcl-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-debuginfo-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-debuginfo-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-devel-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-docs-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-docs-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-perl-2.6.6-6.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-perl-2.6.6-6.el6_0")) flag++;


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
