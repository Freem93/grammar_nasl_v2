#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0740. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25797);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/29 15:45:03 $");

  script_cve_id("CVE-2007-2926");
  script_bugtraq_id(25037);
  script_osvdb_id(36235);
  script_xref(name:"RHSA", value:"2007:0740");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : bind (RHSA-2007:0740)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ISC BIND (Berkeley Internet Name Domain) is an implementation of the
DNS (Domain Name System) protocols.

A flaw was found in the way BIND generates outbound DNS query ids. If
an attacker is able to acquire a finite set of query IDs, it becomes
possible to accurately predict future query IDs. Future query ID
prediction may allow an attacker to conduct a DNS cache poisoning
attack, which can result in the DNS server returning incorrect client
query data. (CVE-2007-2926)

Users of BIND are advised to upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2926.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0740.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/24");
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
  rhsa = "RHSA-2007:0740";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-9.2.1-9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-devel-9.2.1-9.el2")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bind-utils-9.2.1-9.el2")) flag++;


  if (rpm_check(release:"RHEL3", reference:"bind-9.2.4-21.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-chroot-9.2.4-21.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-devel-9.2.4-21.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-libs-9.2.4-21.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bind-utils-9.2.4-21.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"bind-9.2.4-27.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-chroot-9.2.4-27.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-devel-9.2.4-27.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-libs-9.2.4-27.0.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bind-utils-9.2.4-27.0.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-chroot-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-devel-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libbind-devel-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libs-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-sdb-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-utils-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"caching-nameserver-9.3.3-9.0.1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libbind-devel / bind-libs / etc");
  }
}
