#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0737 and 
# CentOS Errata and Security Advisory 2013:0737 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65932);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849");
  script_bugtraq_id(58323, 58895, 58896, 58897);
  script_osvdb_id(92090, 92091, 92093, 92094);
  script_xref(name:"RHSA", value:"2013:0737");

  script_name(english:"CentOS 5 / 6 : subversion (CESA-2013:0737)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix multiple security issues are now
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
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019687.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ccd36e8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-April/019688.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b7d329d"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-svn2cl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"mod_dav_svn-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-devel-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-javahl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-perl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-ruby-1.6.11-11.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"mod_dav_svn-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-devel-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-gnome-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-javahl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-kde-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-perl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-ruby-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-svn2cl-1.6.11-9.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
