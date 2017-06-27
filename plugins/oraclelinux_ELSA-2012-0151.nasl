#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-0151.
#

include("compat.inc");

if (description)
{
  script_id(68469);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2010-1104", "CVE-2011-1948", "CVE-2011-4924");
  script_bugtraq_id(37765, 48005);

  script_name(english:"Oracle Linux 5 : conga (ELSA-2012-0151)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[0.12.2-51.0.1.el5]
- Added conga-enterprise.patch
- Added conga-enterprise-Carthage.patch to support OEL5
- Replaced redhat logo image in conga-0.12.2.tar.gz

[0.12.2-51]
- Fix bz711494 (CVE-2011-1948 plone: reflected XSS vulnerability)
- Fix bz771920 (CVE-2011-4924 Zope: Incomplete upstream patch for 
CVE-2010-1104/bz577019)

[0.12.2-45]
- Fix bz751359 (Add luci support for fence_ipmilan's -L option)

[0.12.2-44]
- Fix bz577019 (CVE-2010-1104 zope: XSS on error page)

[0.12.2-42]
- Fix bz755935 (luci_admin man page is misleading)
- Fix bz755941 (luci_admin restore is not consistent)

[0.12.2-40]
- Fix excluding busy nodes not working properly in luci internals.

[0.12.2-38]
- Additional fix for bz734562 (Improve Luci's resource name validation)

[0.12.2-37]
- Additional fix for bz734562 (Improve Luci's resource name validation)

[0.12.2-36]
- Bump version of the luci database.

[0.12.2-35]
- Fix bz739600 (conga allows erroneous characters in resource)
- Fix bz734562 (Improve Luci's resource name validation)

[0.12.2-34]
- Fix bz709478 (Ricci fails to detect if host if virtual machine capable)
- Fix bz723000 (Modifying an existing shared resource will not update 
the reference in the cluster.conf)
- Fix bz723188 (Luci does not allow to modify __max_restarts and 
__restart_expire_time for independent subtrees, only for non-critical 
resources)

[0.12.2-33]
- Fix bz732483 (Create new cluster fails with luci when installing 
packages.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002649.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
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
if (rpm_check(release:"EL5", reference:"luci-0.12.2-51.0.1.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ricci-0.12.2-51.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "luci / ricci");
}
