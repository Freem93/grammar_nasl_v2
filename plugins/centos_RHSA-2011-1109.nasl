#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1109 and 
# CentOS Errata and Security Advisory 2011:1109 respectively.
#

include("compat.inc");

if (description)
{
  script_id(55839);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2011-2697");
  script_xref(name:"RHSA", value:"2011:1109");

  script_name(english:"CentOS 4 / 5 : foomatic (CESA-2011:1109)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated foomatic package that fixes one security issue is now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Foomatic is a comprehensive, spooler-independent database of printers,
printer drivers, and driver descriptions. The package also includes
spooler-independent command line interfaces to manipulate queues and
to print files and manipulate print jobs. foomatic-rip is a print
filter written in Perl.

An input sanitization flaw was found in the foomatic-rip print filter.
An attacker could submit a print job with the username, title, or job
options set to appear as a command line option that caused the filter
to use a specified PostScript printer description (PPD) file, rather
than the administrator-set one. This could lead to arbitrary code
execution with the privileges of the 'lp' user. (CVE-2011-2697)

All foomatic users should upgrade to this updated package, which
contains a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?256849b0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-August/017666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5f50679"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?455f1b86"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-September/017826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c786395"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f4aee65"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2011-September/000243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed56b2a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected foomatic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:foomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"foomatic-3.0.2-3.2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"foomatic-3.0.2-3.2.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"foomatic-3.0.2-38.3.el5_7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
