#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1206 and 
# CentOS Errata and Security Advisory 2012:1206 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61682);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/29 00:03:02 $");

  script_cve_id("CVE-2012-0878");
  script_osvdb_id(79615);
  script_xref(name:"RHSA", value:"2012:1206");

  script_name(english:"CentOS 6 : python-paste-script (CESA-2012:1206)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated python-paste-script package that fixes one security issue
is now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Python Paste provides middleware for building and running Python web
applications. The python-paste-script package includes paster, a tool
for working with and running Python Paste applications.

It was discovered that paster did not drop supplementary group
privileges when started by the root user. Running 'paster serve' as
root to start a Python web application that will run as a non-root
user and group resulted in that application running with root group
privileges. This could possibly allow a remote attacker to gain access
to files that should not be accessible to the application.
(CVE-2012-0878)

All paster users should upgrade to this updated package, which
contains a backported patch to resolve this issue. All running paster
instances configured to drop privileges must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed4e0deb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-paste-script package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-paste-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"python-paste-script-1.7.3-5.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
