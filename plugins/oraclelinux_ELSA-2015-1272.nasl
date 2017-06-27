#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-1272.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85097);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/08/07 16:58:40 $");

  script_cve_id(
    "CVE-2011-5321",
    "CVE-2012-6657",
    "CVE-2014-3184",
    "CVE-2014-3185",
    "CVE-2014-3215",
    "CVE-2014-3610",
    "CVE-2014-3611",
    "CVE-2014-3645",
    "CVE-2014-3646",
    "CVE-2014-3673",
    "CVE-2014-3687",
    "CVE-2014-3688",
    "CVE-2014-3690",
    "CVE-2014-3940",
    "CVE-2014-4652",
    "CVE-2014-4656",
    "CVE-2014-5471",
    "CVE-2014-5472",
    "CVE-2014-6410",
    "CVE-2014-7822",
    "CVE-2014-7825",
    "CVE-2014-7826",
    "CVE-2014-7841",
    "CVE-2014-8133",
    "CVE-2014-8159",
    "CVE-2014-8369",
    "CVE-2014-8709",
    "CVE-2014-8884",
    "CVE-2014-9322",
    "CVE-2014-9419",
    "CVE-2014-9420",
    "CVE-2014-9529",
    "CVE-2014-9584",
    "CVE-2014-9585",
    "CVE-2014-9683",
    "CVE-2015-0239",
    "CVE-2015-1593",
    "CVE-2015-1805",
    "CVE-2015-2830",
    "CVE-2015-2922",
    "CVE-2015-3331",
    "CVE-2015-3339",
    "CVE-2015-3636"
  );

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2015-1272)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux host is missing a security update for one or
more kernel-related packages.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005242.html");
  script_set_attribute(attribute:"solution", value:"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

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
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL6", reference:"kernel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-abi-whitelists-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-573.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
