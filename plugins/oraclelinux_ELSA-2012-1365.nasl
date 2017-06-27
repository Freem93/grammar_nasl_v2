#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-1365.
#

include("compat.inc");

if (description)
{
  script_id(68642);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2012-4244", "CVE-2012-5166");
  script_bugtraq_id(55522, 55852);

  script_name(english:"Oracle Linux 4 : bind (ELSA-2012-1365)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[20:9.2.4-38.0.2.el4]
- fix CVE-2012-4244 (Adam Tkac) [orabz 14518]
- fix CVE-2012-5166 (Adam Tkac) [orabz 14518]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-November/003156.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/29");
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
if (rpm_check(release:"EL4", reference:"bind-9.2.4-38.0.2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"bind-chroot-9.2.4-38.0.2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"bind-devel-9.2.4-38.0.2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"bind-libs-9.2.4-38.0.2.el4")) flag++;
if (rpm_check(release:"EL4", reference:"bind-utils-9.2.4-38.0.2.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-devel / bind-libs / bind-utils");
}
