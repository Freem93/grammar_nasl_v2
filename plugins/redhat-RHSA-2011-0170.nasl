#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0170. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51590);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2011-0002");
  script_bugtraq_id(45791);
  script_osvdb_id(70421);
  script_xref(name:"RHSA", value:"2011:0170");

  script_name(english:"RHEL 4 / 5 / 6 : libuser (RHSA-2011:0170)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libuser packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libuser library implements a standardized interface for
manipulating and administering user and group accounts. Sample
applications that are modeled after applications from the shadow
password suite (shadow-utils) are included in these packages.

It was discovered that libuser did not set the password entry
correctly when creating LDAP (Lightweight Directory Access Protocol)
users. If an administrator did not assign a password to an LDAP based
user account, either at account creation with luseradd, or with
lpasswd after account creation, an attacker could use this flaw to log
into that account with a default password string that should have been
rejected. (CVE-2011-0002)

Note: LDAP administrators that have used libuser tools to add users
should check existing user accounts for plain text passwords, and
reset them as necessary.

Users of libuser should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0170.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libuser-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0170";
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
  if (rpm_check(release:"RHEL4", reference:"libuser-0.52.5-1.1.el4_8.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"libuser-devel-0.52.5-1.1.el4_8.1")) flag++;


  if (rpm_check(release:"RHEL5", reference:"libuser-0.54.7-2.1.el5_5.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libuser-devel-0.54.7-2.1.el5_5.2")) flag++;


  if (rpm_check(release:"RHEL6", reference:"libuser-0.56.13-4.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libuser-debuginfo-0.56.13-4.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libuser-devel-0.56.13-4.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libuser-python-0.56.13-4.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libuser-python-0.56.13-4.el6_0.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libuser-python-0.56.13-4.el6_0.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuser / libuser-debuginfo / libuser-devel / libuser-python");
  }
}
