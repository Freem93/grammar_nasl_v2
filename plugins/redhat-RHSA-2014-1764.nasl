#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1764. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78758);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-4877");
  script_osvdb_id(113736);
  script_xref(name:"RHSA", value:"2014:1764");

  script_name(english:"RHEL 6 / 7 : wget (RHSA-2014:1764)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated wget package that fixes one security issue is now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The wget package provides the GNU Wget file retrieval utility for
HTTP, HTTPS, and FTP protocols.

A flaw was found in the way Wget handled symbolic links. A malicious
FTP server could allow Wget running in the mirror mode (using the '-m'
command line option) to write an arbitrary file to a location writable
to by the user running Wget, possibly leading to code execution.
(CVE-2014-4877)

Note: This update changes the default value of the --retr-symlinks
option. The file symbolic links are now traversed by default and
pointed-to files are retrieved rather than creating a symbolic link
locally.

Red Hat would like to thank the GNU Wget project for reporting this
issue. Upstream acknowledges HD Moore of Rapid7, Inc as the original
reporter.

All users of wget are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1764.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wget and / or wget-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wget-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1764";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"wget-1.12-5.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"wget-1.12-5.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"wget-1.12-5.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"wget-debuginfo-1.12-5.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"wget-debuginfo-1.12-5.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"wget-debuginfo-1.12-5.el6_6.1")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"wget-1.14-10.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"wget-1.14-10.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"wget-debuginfo-1.14-10.el7_0.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"wget-debuginfo-1.14-10.el7_0.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wget / wget-debuginfo");
  }
}
