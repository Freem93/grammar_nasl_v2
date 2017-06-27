#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0961 and 
# CentOS Errata and Security Advisory 2007:0961 respectively.
#

include("compat.inc");

if (description)
{
  script_id(37552);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-6303", "CVE-2007-5162", "CVE-2007-5770");
  script_bugtraq_id(25847, 26421);
  script_osvdb_id(11534, 40773);
  script_xref(name:"RHSA", value:"2007:0961");

  script_name(english:"CentOS 4 : ruby (CESA-2007:0961)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for object-oriented
programming.

A flaw was discovered in the way Ruby's CGI module handles certain
HTTP requests. If a remote attacker sends a specially crafted request,
it is possible to cause the ruby CGI script to enter an infinite loop,
possibly causing a denial of service. (CVE-2006-6303)

An SSL certificate validation flaw was discovered in several Ruby Net
modules. The libraries were not checking the requested host name
against the common name (CN) in the SSL server certificate, possibly
allowing a man in the middle attack. (CVE-2007-5162, CVE-2007-5770)

Users of Ruby should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad9afa20"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05605539"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?599b7568"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"irb-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-devel-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-docs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-libs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-mode-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ruby-tcltk-1.8.1-7.EL4.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
