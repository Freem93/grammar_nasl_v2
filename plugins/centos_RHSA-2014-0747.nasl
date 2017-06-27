#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0747 and 
# CentOS Errata and Security Advisory 2014:0747 respectively.
#

include("compat.inc");

if (description)
{
  script_id(74475);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/12 10:50:12 $");

  script_cve_id("CVE-2014-1402");
  script_xref(name:"RHSA", value:"2014:0747");

  script_name(english:"CentOS 6 : python-jinja2 (CESA-2014:0747)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python-jinja2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Jinja2 is a template engine written in pure Python. It provides a
Django-inspired, non-XML syntax but supports inline expressions and an
optional sandboxed environment.

It was discovered that Jinja2 did not properly handle bytecode cache
files stored in the system's temporary directory. A local attacker
could use this flaw to alter the output of an application using Jinja2
and FileSystemBytecodeCache, and potentially execute arbitrary code
with the privileges of that application. (CVE-2014-1402)

All python-jinja2 users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue. For
the update to take effect, all applications using python-jinja2 must
be restarted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-June/020367.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23ea64bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-jinja2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"python-jinja2-2.2.1-2.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
