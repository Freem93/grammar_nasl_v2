#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1419 and 
# Oracle Linux Security Advisory ELSA-2015-1419 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85106);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:38:00 $");

  script_cve_id("CVE-2015-1819");
  script_bugtraq_id(75570);
  script_osvdb_id(120600);
  script_xref(name:"RHSA", value:"2015:1419");

  script_name(english:"Oracle Linux 6 : libxml2 (ELSA-2015-1419)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1419 :

Updated libxml2 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

A denial of service flaw was found in the way the libxml2 library
parsed certain XML files. An attacker could provide a specially
crafted XML file that, when parsed by an application using libxml2,
could cause that application to use an excessive amount of memory.
(CVE-2015-1819)

This issue was discovered by Florian Weimer of Red Hat Product
Security.

This update also fixes the following bug :

This update fixes an error that occurred when running a test case for
the serialization of HTML documents. (BZ#1004513)

Users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005233.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"libxml2-2.7.6-20.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-devel-2.7.6-20.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-python-2.7.6-20.0.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-static-2.7.6-20.0.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python / libxml2-static");
}
