#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1707 and 
# Oracle Linux Security Advisory ELSA-2015-1707 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85779);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2015-5722");
  script_osvdb_id(126995);
  script_xref(name:"RHSA", value:"2015:1707");

  script_name(english:"Oracle Linux 5 : bind97 (ELSA-2015-1707)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1707 :

Updated bind97 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A denial of service flaw was found in the way BIND parsed certain
malformed DNSSEC keys. A remote attacker could use this flaw to send a
specially crafted DNS query (for example, a query requiring a response
from a zone containing a deliberately malformed key) that would cause
named functioning as a validating resolver to crash. (CVE-2015-5722)

Red Hat would like to thank ISC for reporting this issue. Upstream
acknowledges Hanno Bock as the original reporter.

All bind97 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-September/005384.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind97 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"bind97-9.7.0-21.P2.el5_11.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-chroot-9.7.0-21.P2.el5_11.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-devel-9.7.0-21.P2.el5_11.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-libs-9.7.0-21.P2.el5_11.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-utils-9.7.0-21.P2.el5_11.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind97 / bind97-chroot / bind97-devel / bind97-libs / bind97-utils");
}
