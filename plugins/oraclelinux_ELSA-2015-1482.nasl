#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1482 and 
# Oracle Linux Security Advisory ELSA-2015-1482 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85115);
  script_version("$Revision: 2.16 $");
  script_cvs_date("$Date: 2016/06/27 14:13:07 $");

  script_cve_id("CVE-2015-3245", "CVE-2015-3246");
  script_bugtraq_id(76021, 76022);
  script_osvdb_id(125263, 125264);
  script_xref(name:"RHSA", value:"2015:1482");
  script_xref(name:"IAVA", value:"2015-A-0179");

  script_name(english:"Oracle Linux 6 : libuser (ELSA-2015-1482)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1482 :

Updated libuser packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libuser library implements a standardized interface for
manipulating and administering user and group accounts. Sample
applications that are modeled after applications from the shadow
password suite (shadow-utils) are included in these packages.

Two flaws were found in the way the libuser library handled the
/etc/passwd file. A local attacker could use an application compiled
against libuser (for example, userhelper) to manipulate the
/etc/passwd file, which could result in a denial of service or
possibly allow the attacker to escalate their privileges to root.
(CVE-2015-3245, CVE-2015-3246)

Red Hat would like to thank Qualys for reporting these issues.

All libuser users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005247.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libuser-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libuser-0.56.13-8.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libuser-devel-0.56.13-8.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"libuser-python-0.56.13-8.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuser / libuser-devel / libuser-python");
}
