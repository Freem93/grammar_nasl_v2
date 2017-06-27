#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0423. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53311);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 16:02:21 $");

  script_cve_id("CVE-2011-0411");
  script_osvdb_id(71021, 71946, 72186);
  script_xref(name:"RHSA", value:"2011:0423");

  script_name(english:"RHEL 6 : postfix (RHSA-2011:0423)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated postfix packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH
(SASL), and TLS.

It was discovered that Postfix did not flush the received SMTP
commands buffer after switching to TLS encryption for an SMTP session.
A man-in-the-middle attacker could use this flaw to inject SMTP
commands into a victim's session during the plain text phase. This
would lead to those commands being processed by Postfix after TLS
encryption is enabled, possibly allowing the attacker to steal the
victim's mail or authentication credentials. (CVE-2011-0411)

Red Hat would like to thank the CERT/CC for reporting CVE-2011-0411.
The CERT/CC acknowledges Wietse Venema as the original reporter.

Users of Postfix are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the postfix service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0423.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected postfix, postfix-debuginfo and / or
postfix-perl-scripts packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postfix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postfix-perl-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");
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
  rhsa = "RHSA-2011:0423";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postfix-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postfix-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postfix-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postfix-debuginfo-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postfix-debuginfo-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postfix-debuginfo-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"postfix-perl-scripts-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"postfix-perl-scripts-2.6.6-2.1.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"postfix-perl-scripts-2.6.6-2.1.el6_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postfix / postfix-debuginfo / postfix-perl-scripts");
  }
}
