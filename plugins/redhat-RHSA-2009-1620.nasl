#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1620. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42946);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:27:03 $");

  script_cve_id("CVE-2009-4022");
  script_bugtraq_id(37118);
  script_osvdb_id(60493);
  script_xref(name:"RHSA", value:"2009:1620");

  script_name(english:"RHEL 5 : bind (RHSA-2009:1620)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

Michael Sinatra discovered that BIND was incorrectly caching responses
without performing proper DNSSEC validation, when those responses were
received during the resolution of a recursive client query that
requested DNSSEC records but indicated that checking should be
disabled. A remote attacker could use this flaw to bypass the DNSSEC
validation check and perform a cache poisoning attack if the target
BIND server was receiving such client queries. (CVE-2009-4022)

All BIND users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
update, the BIND daemon (named) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1620.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1620";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-chroot-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-chroot-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-chroot-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-devel-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bind-libs-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-sdb-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-sdb-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-sdb-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bind-utils-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bind-utils-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bind-utils-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"caching-nameserver-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"caching-nameserver-9.3.6-4.P1.el5_4.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"caching-nameserver-9.3.6-4.P1.el5_4.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
