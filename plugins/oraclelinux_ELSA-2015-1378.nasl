#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1378 and 
# Oracle Linux Security Advisory ELSA-2015-1378 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85102);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2014-9273");
  script_bugtraq_id(71279);
  script_osvdb_id(115209);
  script_xref(name:"RHSA", value:"2015:1378");

  script_name(english:"Oracle Linux 6 : hivex (ELSA-2015-1378)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1378 :

Updated hivex packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hivex is a library that can read and write Hive files, undocumented
binary files that Windows uses to store the Windows Registry on disk.

It was found that hivex attempted to read, and possibly write, beyond
its allocated buffer when reading a hive file with a very small size
or with a truncated or improperly formatted content. An attacker able
to supply a specially crafted hive file to an application using the
hivex library could possibly use this flaw to execute arbitrary code
with the privileges of the user running that application.
(CVE-2014-9273)

Red Hat would like to thank Mahmoud Al-Qudsi of NeoSmart Technologies
for reporting this issue.

This update also fixes the following bug :

* The hivex(3) man page previously contained a typographical error.
This update fixes the typo. (BZ#1164693)

All hivex users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005238.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hivex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-hivex");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"hivex-devel-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"ocaml-hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"perl-hivex-1.3.3-4.3.el6")) flag++;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"python-hivex-1.3.3-4.3.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-devel / ocaml-hivex / ocaml-hivex-devel / perl-hivex / etc");
}
