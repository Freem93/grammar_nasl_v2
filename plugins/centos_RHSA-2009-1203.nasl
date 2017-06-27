#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1203 and 
# CentOS Errata and Security Advisory 2009:1203 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43775);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/19 14:28:09 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_osvdb_id(56856);
  script_xref(name:"RHSA", value:"2009:1203");

  script_name(english:"CentOS 5 : subversion (CESA-2009:1203)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.

Matt Lewis, of Google, reported multiple heap overflow flaws in
Subversion (server and client) when parsing binary deltas. A malicious
user with commit access to a server could use these flaws to cause a
heap overflow on that server. A malicious server could use these flaws
to cause a heap overflow on a client when it attempts to checkout or
update. These heap overflows can result in a crash or, possibly,
arbitrary code execution. (CVE-2009-2411)

All Subversion users should upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
the updated packages, the Subversion server must be restarted for the
update to take effect: restart httpd if you are using mod_dav_svn, or
restart svnserve if it is used."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016070.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73b9f5e1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016071.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7625f2f0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"mod_dav_svn-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-devel-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-javahl-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-perl-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-ruby-1.4.2-4.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
