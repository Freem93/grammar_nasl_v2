#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1635 and 
# Oracle Linux Security Advisory ELSA-2015-1635 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85491);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416");
  script_osvdb_id(120909, 120943, 120944);
  script_xref(name:"RHSA", value:"2015:1635");

  script_name(english:"Oracle Linux 7 : sqlite (ELSA-2015-1635)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1635 :

An updated sqlite package that fixes three security issues is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

SQLite is a C library that implements a SQL database engine. A large
subset of SQL92 is supported. A complete database is stored in a
single disk file. The API is designed for convenience and ease of use.
Applications that link against SQLite can enjoy the power and
flexibility of a SQL database without the administrative hassles of
supporting a separate database server.

A flaw was found in the way SQLite handled dequoting of
collation-sequence names. A local attacker could submit a specially
crafted COLLATE statement that would crash the SQLite process, or have
other unspecified impacts. (CVE-2015-3414)

It was found that SQLite's sqlite3VdbeExec() function did not properly
implement comparison operators. A local attacker could submit a
specially crafted CHECK statement that would crash the SQLite process,
or have other unspecified impacts. (CVE-2015-3415)

It was found that SQLite's sqlite3VXPrintf() function did not properly
handle precision and width values during floating-point conversions. A
local attacker could submit a specially crafted SELECT statement that
would crash the SQLite process, or have other unspecified impacts.
(CVE-2015-3416)

All sqlite users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-August/005344.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sqlite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"lemon-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sqlite-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sqlite-devel-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sqlite-doc-3.7.17-6.el7_1.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sqlite-tcl-3.7.17-6.el7_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lemon / sqlite / sqlite-devel / sqlite-doc / sqlite-tcl");
}
