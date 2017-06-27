#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0208 and 
# Oracle Linux Security Advisory ELSA-2007-0208 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67474);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:16:27 $");

  script_cve_id("CVE-2005-3183");
  script_xref(name:"RHSA", value:"2007:0208");

  script_name(english:"Oracle Linux 4 : w3c-libwww (ELSA-2007-0208)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0208 :

Updated w3c-libwww packages that fix a security issue and a bug are
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

w3c-libwww is a general-purpose web library.

Several buffer overflow flaws in w3c-libwww were found. If a client
application that uses w3c-libwww connected to a malicious HTTP server,
it could trigger an out of bounds memory access, causing the client
application to crash (CVE-2005-3183).

This updated version of w3c-libwww also fixes an issue when computing
MD5 sums on a 64 bit machine.

Users of w3c-libwww should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-May/000143.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected w3c-libwww packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:w3c-libwww");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:w3c-libwww-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:w3c-libwww-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"w3c-libwww-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"w3c-libwww-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"w3c-libwww-apps-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"w3c-libwww-apps-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"w3c-libwww-devel-5.4.0-10.1.RHEL4.2")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"w3c-libwww-devel-5.4.0-10.1.RHEL4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3c-libwww / w3c-libwww-apps / w3c-libwww-devel");
}
