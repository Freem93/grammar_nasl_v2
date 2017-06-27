#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# adapted from Red Hat Security Advisory RHSA-2015:1741. That text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85977);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2015-3281");
  script_bugtraq_id(75554);
  script_osvdb_id(124154);
  script_xref(name:"RHSA", value:"2015:1741");

  script_name(english:"RHEL 6 / 7 : haproxy 1.5 (RHSA-2015:1741)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An updated haproxy package that fixes one security issue is now
available for Red Hat Enterprise Linux 6 and 7. HAProxy provides high
availability, load balancing, and proxying for TCP and HTTP-based
applications.

An implementation error related to the memory management of request
and responses was found within HAProxy's buffer_slow_realign()
function. An unauthenticated, remote attacker could possibly use this
flaw to leak certain memory buffer contents from a past request or
session. (CVE-2015-3281)

Note that, according to CVE-2015-3281, this issue only exists in
HAProxy version 1.5.x prior to 1.5.14. All HAProxy users are advised
to upgrade to this updated package, which contains a backported patch
to correct this issue.");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2015-3281.html");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2015-1741.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected haproxy and / or haproxy-debuginfo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_exists(release:"RHEL6", rpm:"haproxy-1.5") && rpm_check(release:"RHEL6", cpu:"i686", reference:"haproxy-1.5.4-2.el6_7.1")) flag++;
if (rpm_exists(release:"RHEL6", rpm:"haproxy-1.5") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"haproxy-1.5.4-2.el6_7.1")) flag++;
if (rpm_exists(release:"RHEL6", rpm:"haproxy-1.5") && rpm_check(release:"RHEL6", cpu:"i686", reference:"haproxy-debuginfo-1.5.4-2.el6_7.1")) flag++;
if (rpm_exists(release:"RHEL6", rpm:"haproxy-1.5") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"haproxy-debuginfo-1.5.4-2.el6_7.1")) flag++;

if (rpm_exists(release:"RHEL7", rpm:"haproxy-1.5") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"haproxy-1.5.4-4.el7_1.1")) flag++;
if (rpm_exists(release:"RHEL7", rpm:"haproxy-1.5") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"haproxy-debuginfo-1.5.4-4.el7_1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "haproxy 1.5 / haproxy-debuginfo 1.5");
}
