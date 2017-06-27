#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-0290.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81800);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/07 16:58:40 $");

  script_cve_id(
    "CVE-2013-2929",
    "CVE-2014-0181",
    "CVE-2014-0196",
    "CVE-2014-0206",
    "CVE-2014-1737",
    "CVE-2014-1738",
    "CVE-2014-1739",
    "CVE-2014-2568",
    "CVE-2014-2672",
    "CVE-2014-2673",
    "CVE-2014-2706",
    "CVE-2014-2851",
    "CVE-2014-3144",
    "CVE-2014-3145",
    "CVE-2014-3153",
    "CVE-2014-3181",
    "CVE-2014-3182",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3186",
    "CVE-2014-3534",
    "CVE-2014-3611",
    "CVE-2014-3631",
    "CVE-2014-3646",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-3688",
    "CVE-2014-3690",
    "CVE-2014-3917",
    "CVE-2014-3940",
    "CVE-2014-4027",
    "CVE-2014-4171",
    "CVE-2014-4652",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-4656",
    "CVE-2014-4667",
    "CVE-2014-4699",
    "CVE-2014-4943",
    "CVE-2014-5045",
    "CVE-2014-5077",
    "CVE-2014-5471",
    "CVE-2014-5472",
    "CVE-2014-6410",
    "CVE-2014-6416",
    "CVE-2014-7145",
    "CVE-2014-7825",
    "CVE-2014-7826",
    "CVE-2014-7841",
    "CVE-2014-8086",
    "CVE-2014-8884",
    "CVE-2014-9322"
  );

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2015-0290)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux host is missing a security update for one or
more kernel-related packages.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2015-March/004880.html");
  script_set_attribute(attribute:"solution", value:"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android \'Towelroot\' Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
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
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-229.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-229.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
