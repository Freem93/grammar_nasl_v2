#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0166 and 
# Oracle Linux Security Advisory ELSA-2015-0166 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81289);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 19:01:51 $");

  script_cve_id("CVE-2014-3528", "CVE-2014-3580", "CVE-2014-8108");
  script_bugtraq_id(68995, 71725, 71726);
  script_osvdb_id(109748, 115921, 115922);
  script_xref(name:"RHSA", value:"2015:0166");

  script_name(english:"Oracle Linux 7 : subversion (ELSA-2015-0166)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:0166 :

Updated subversion packages that fix three security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled REPORT requests. A remote, unauthenticated attacker
could use a specially crafted REPORT request to crash mod_dav_svn.
(CVE-2014-3580)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled certain requests for URIs that trigger a lookup of a
virtual transaction name. A remote, unauthenticated attacker could
send a request for a virtual transaction name that does not exist,
causing mod_dav_svn to crash. (CVE-2014-8108)

It was discovered that Subversion clients retrieved cached
authentication credentials using the MD5 hash of the server realm
string without also checking the server's URL. A malicious server able
to provide a realm that triggers an MD5 collision could possibly use
this flaw to obtain the credentials for a different realm.
(CVE-2014-3528)

Red Hat would like to thank the Subversion project for reporting
CVE-2014-3580 and CVE-2014-8108. Upstream acknowledges Evgeny Kotkov
of VisualSVN as the original reporter.

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-February/004840.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/11");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-devel-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-kde-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-libs-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-perl-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-python-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-7.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-tools-1.7.14-7.el7_0")) flag++;


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
