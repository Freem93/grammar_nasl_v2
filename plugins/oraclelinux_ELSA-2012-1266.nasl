#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1266 and 
# Oracle Linux Security Advisory ELSA-2012-1266 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68623);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:07:16 $");

  script_cve_id("CVE-2012-4244");
  script_osvdb_id(85417);
  script_xref(name:"RHSA", value:"2012:1266");

  script_name(english:"Oracle Linux 5 : bind97 (ELSA-2012-1266)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1266 :

Updated bind97 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handled resource records with a large
RDATA value. A malicious owner of a DNS domain could use this flaw to
create specially crafted DNS resource records, that would cause a
recursive resolver or secondary server to exit unexpectedly with an
assertion failure. (CVE-2012-4244)

Users of bind97 are advised to upgrade to these updated packages,
which correct this issue. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-September/003032.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind97 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL5", reference:"bind97-9.7.0-10.P2.el5_8.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-chroot-9.7.0-10.P2.el5_8.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-devel-9.7.0-10.P2.el5_8.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-libs-9.7.0-10.P2.el5_8.3")) flag++;
if (rpm_check(release:"EL5", reference:"bind97-utils-9.7.0-10.P2.el5_8.3")) flag++;


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
