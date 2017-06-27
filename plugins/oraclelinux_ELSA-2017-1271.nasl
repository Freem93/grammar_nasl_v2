#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:1271 and 
# Oracle Linux Security Advisory ELSA-2017-1271 respectively.
#

include("compat.inc");

if (description)
{
  script_id(100397);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2017-7494");
  script_xref(name:"RHSA", value:"2017:1271");

  script_name(english:"Oracle Linux 6 : samba4 (ELSA-2017-1271)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:1271 :

An update for samba4 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* A remote code execution flaw was found in Samba. A malicious
authenticated samba client, having write access to the samba share,
could use this flaw to execute arbitrary code as root. (CVE-2017-7494)

Red Hat would like to thank the Samba project for reporting this
issue. Upstream acknowledges steelo as the original reporter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-May/006925.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba4 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"samba4-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-client-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-common-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-dc-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-dc-libs-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-devel-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-libs-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-pidl-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-python-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-test-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-clients-4.2.10-10.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"samba4-winbind-krb5-locator-4.2.10-10.el6_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
}
