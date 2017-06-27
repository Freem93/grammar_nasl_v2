#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0079. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88480);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/10 20:34:11 $");

  script_cve_id("CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000");
  script_osvdb_id(125438, 126995, 131837);
  script_xref(name:"RHSA", value:"2016:0079");

  script_name(english:"RHEL 6 : bind (RHSA-2016:0079)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.6 Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handled requests for TKEY DNS
resource records. A remote attacker could use this flaw to make named
(functioning as an authoritative DNS server or a DNS resolver) exit
unexpectedly with an assertion failure via a specially crafted DNS
request packet. (CVE-2015-5477)

A denial of service flaw was found in the way BIND parsed certain
malformed DNSSEC keys. A remote attacker could use this flaw to send a
specially crafted DNS query (for example, a query requiring a response
from a zone containing a deliberately malformed key) that would cause
named functioning as a validating resolver to crash. (CVE-2015-5722)

A denial of service flaw was found in the way BIND processed certain
records with malformed class attributes. A remote attacker could use
this flaw to send a query to request a cached record with a malformed
class attribute that would cause named functioning as an authoritative
or recursive server to crash. (CVE-2015-8000)

Note: This issue affects authoritative servers as well as recursive
servers, however authoritative servers are at limited risk if they
perform authentication when making recursive queries to resolve
addresses for servers listed in NS RRSETs.

Red Hat would like to thank ISC for reporting the CVE-2015-5477,
CVE-2015-5722, and CVE-2015-8000 issues. Upstream acknowledges
Jonathan Foote as the original reporter of CVE-2015-5477, and Hanno
Bock as the original reporter of CVE-2015-5722.

All bind users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-8000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.isc.org/article/AA-01317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0079.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.6", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0079";
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
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"bind-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"bind-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"bind-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"bind-chroot-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"bind-chroot-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"bind-chroot-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"bind-debuginfo-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"bind-devel-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"bind-libs-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"bind-sdb-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"bind-sdb-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"bind-sdb-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"bind-utils-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"bind-utils-9.8.2-0.30.rc1.el6_6.4")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"bind-utils-9.8.2-0.30.rc1.el6_6.4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
  }
}
