#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0790. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76244);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 15:40:58 $");

  script_cve_id("CVE-2014-3430");
  script_xref(name:"RHSA", value:"2014:0790");

  script_name(english:"RHEL 6 / 7 : dovecot (RHSA-2014:0790)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dovecot packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Dovecot is an IMAP server, written with security primarily in mind,
for Linux and other UNIX-like systems. It also contains a small POP3
server. It supports mail in both the maildir or mbox format. The SQL
drivers and authentication plug-ins are provided as subpackages.

It was discovered that Dovecot did not properly discard connections
trapped in the SSL/TLS handshake phase. A remote attacker could use
this flaw to cause a denial of service on an IMAP/POP3 server by
exhausting the pool of available connections and preventing further,
legitimate connections to the IMAP/POP3 server to be made.
(CVE-2014-3430)

All dovecot users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the updated packages, the dovecot service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0790.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2014:0790";
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
  if (rpm_check(release:"RHEL6", reference:"dovecot-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"dovecot-debuginfo-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-devel-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-devel-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-devel-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-mysql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-mysql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-mysql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-pgsql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-pgsql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-pgsql-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"dovecot-pigeonhole-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"dovecot-pigeonhole-2.0.9-7.el6_5.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"dovecot-pigeonhole-2.0.9-7.el6_5.1")) flag++;


  if (rpm_check(release:"RHEL7", reference:"dovecot-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"dovecot-debuginfo-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"dovecot-mysql-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"dovecot-mysql-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"dovecot-pgsql-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"dovecot-pgsql-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"dovecot-pigeonhole-2.2.10-4.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"dovecot-pigeonhole-2.2.10-4.el7_0.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-debuginfo / dovecot-devel / dovecot-mysql / etc");
  }
}
