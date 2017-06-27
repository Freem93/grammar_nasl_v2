#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0737 and 
# Oracle Linux Security Advisory ELSA-2013-0737 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68805);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:16:04 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849");
  script_bugtraq_id(58323, 58895, 58896, 58897);
  script_osvdb_id(92090, 92091, 92093, 92094);
  script_xref(name:"RHSA", value:"2013:0737");

  script_name(english:"Oracle Linux 5 / 6 : subversion (ELSA-2013-0737)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0737 :

Updated subversion packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled PROPFIND requests on activity URLs. A remote attacker
could use this flaw to cause the httpd process serving the request to
crash. (CVE-2013-1849)

A flaw was found in the way the mod_dav_svn module handled large
numbers of properties (such as those set with the 'svn propset'
command). A malicious, remote user could use this flaw to cause the
httpd process serving the request to consume an excessive amount of
system memory. (CVE-2013-1845)

Two NULL pointer dereference flaws were found in the way the
mod_dav_svn module handled LOCK requests on certain types of URLs. A
malicious, remote user could use these flaws to cause the httpd
process serving the request to crash. (CVE-2013-1846, CVE-2013-1847)

Note: The CVE-2013-1849, CVE-2013-1846, and CVE-2013-1847 issues only
caused a temporary denial of service, as the Apache HTTP Server
started a new process to replace the crashed child process. When using
prefork MPM, the crash only affected the attacker. When using worker
(threaded) MPM, the connections of other users may have been
interrupted.

Red Hat would like to thank the Apache Subversion project for
reporting these issues. Upstream acknowledges Alexander Klink as the
original reporter of CVE-2013-1845; Ben Reser as the original reporter
of CVE-2013-1846; and Philip Martin and Ben Reser as the original
reporters of CVE-2013-1847.

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, you must restart the httpd daemon, if you are
using mod_dav_svn, for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003405.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-svn2cl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"mod_dav_svn-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-devel-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-javahl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-perl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-ruby-1.6.11-11.el5_9")) flag++;

if (rpm_check(release:"EL6", reference:"mod_dav_svn-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-devel-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-gnome-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-javahl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-kde-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-perl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-ruby-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-svn2cl-1.6.11-9.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
