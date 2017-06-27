#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1267 and 
# Oracle Linux Security Advisory ELSA-2016-1267 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91737);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-4444", "CVE-2016-4445", "CVE-2016-4446", "CVE-2016-4989");
  script_osvdb_id(140303, 140304, 140305, 140306, 140307);
  script_xref(name:"RHSA", value:"2016:1267");

  script_name(english:"Oracle Linux 6 : setroubleshoot / setroubleshoot-plugins (ELSA-2016-1267)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1267 :

An update for setroubleshoot and setroubleshoot-plugins is now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an
alert can be generated that provides information about the problem and
helps to track its resolution.

The setroubleshoot-plugins package provides a set of analysis plugins
for use with setroubleshoot. Each plugin has the capacity to analyze
SELinux AVC data and system data to provide user friendly reports
describing how to interpret SELinux AVC denials.

Security Fix(es) :

* Shell command injection flaws were found in the way the
setroubleshoot executed external commands. A local attacker able to
trigger certain SELinux denials could use these flaws to execute
arbitrary code with root privileges. (CVE-2016-4445, CVE-2016-4989)

* Shell command injection flaws were found in the way the
setroubleshoot allow_execmod and allow_execstack plugins executed
external commands. A local attacker able to trigger an execmod or
execstack SELinux denial could use these flaws to execute arbitrary
code with root privileges. (CVE-2016-4444, CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos
Malik (Red Hat) and the CVE-2016-4445 and CVE-2016-4989 issues were
discovered by Red Hat Product Security."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006126.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected setroubleshoot and / or setroubleshoot-plugins
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"setroubleshoot-3.0.47-12.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"setroubleshoot-doc-3.0.47-12.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"setroubleshoot-plugins-3.0.40-3.1.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"setroubleshoot-server-3.0.47-12.0.1.el6_8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-doc / setroubleshoot-plugins / etc");
}
