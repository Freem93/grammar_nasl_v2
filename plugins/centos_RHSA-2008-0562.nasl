#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0562 and 
# CentOS Errata and Security Advisory 2008:0562 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33489);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2006-6303", "CVE-2008-2376", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(29903, 30036);
  script_xref(name:"RHSA", value:"2008:0562");

  script_name(english:"CentOS 3 : ruby (CESA-2008:0562)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for quick and easy
object-oriented programming.

Multiple integer overflows leading to a heap overflow were discovered
in the array- and string-handling code used by Ruby. An attacker could
use these flaws to crash a Ruby application or, possibly, execute
arbitrary code with the privileges of the Ruby application using
untrusted inputs in array or string operations. (CVE-2008-2376,
CVE-2008-2663, CVE-2008-2725, CVE-2008-2726)

It was discovered that Ruby used the alloca() memory allocation
function in the format (%) method of the String class without properly
restricting maximum string length. An attacker could use this flaw to
crash a Ruby application or, possibly, execute arbitrary code with the
privileges of the Ruby application using long, untrusted strings as
format strings. (CVE-2008-2664)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

A flaw was discovered in the way Ruby's CGI module handles certain
HTTP requests. A remote attacker could send a specially crafted
request and cause the Ruby CGI script to enter an infinite loop,
possibly causing a denial of service. (CVE-2006-6303)

Users of Ruby should upgrade to these updated packages, which contain
a backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015110.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eac65352"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?154679bd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015125.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d0194aa"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"irb-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-devel-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-docs-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-libs-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-mode-1.6.8-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-tcltk-1.6.8-12.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
