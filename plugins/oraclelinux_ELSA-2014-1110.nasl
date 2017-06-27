#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1110 and 
# Oracle Linux Security Advisory ELSA-2014-1110 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77463);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:02:16 $");

  script_cve_id("CVE-2014-0475", "CVE-2014-5119");
  script_bugtraq_id(68505, 68983);
  script_osvdb_id(108943, 109188);
  script_xref(name:"RHSA", value:"2014:1110");

  script_name(english:"Oracle Linux 5 / 6 / 7 : glibc (ELSA-2014-1110)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1110 :

Updated glibc packages that fix two security issues are now available
for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An off-by-one heap-based buffer overflow flaw was found in glibc's
internal __gconv_translit_find() function. An attacker able to make an
application call the iconv_open() function with a specially crafted
argument could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-5119)

A directory traversal flaw was found in the way glibc loaded locale
files. An attacker able to make an application use a specially crafted
locale name value (for example, specified in an LC_* environment
variable) could possibly use this flaw to execute arbitrary code with
the privileges of that application. (CVE-2014-0475)

Red Hat would like to thank Stephane Chazelas for reporting
CVE-2014-0475.

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-August/004391.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"glibc-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-common-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-devel-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-headers-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"EL5", reference:"glibc-utils-2.5-118.el5_10.3")) flag++;
if (rpm_check(release:"EL5", reference:"nscd-2.5-118.el5_10.3")) flag++;

if (rpm_check(release:"EL6", reference:"glibc-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"glibc-common-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"glibc-devel-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"glibc-headers-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"glibc-static-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"glibc-utils-2.12-1.132.el6_5.4")) flag++;
if (rpm_check(release:"EL6", reference:"nscd-2.12-1.132.el6_5.4")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-common-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-devel-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-headers-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-static-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"glibc-utils-2.17-55.0.4.el7_0.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"nscd-2.17-55.0.4.el7_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc");
}
