#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0896 and 
# CentOS Errata and Security Advisory 2008:0896 respectively.
#

include("compat.inc");

if (description)
{
  script_id(34462);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3905");
  script_bugtraq_id(30644, 30682, 31699);
  script_xref(name:"RHSA", value:"2008:0896");

  script_name(english:"CentOS 3 : ruby (CESA-2008:0896)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for quick and easy
object-oriented programming.

The Ruby DNS resolver library, resolv.rb, used predictable transaction
IDs and a fixed source port when sending DNS requests. A remote
attacker could use this flaw to spoof a malicious reply to a DNS
query. (CVE-2008-3905)

A number of flaws were found in the safe-level restrictions in Ruby.
It was possible for an attacker to create a carefully crafted
malicious script that can allow the bypass of certain safe-level
restrictions. (CVE-2008-3655)

A denial of service flaw was found in Ruby's regular expression
engine. If a Ruby script tried to process a large amount of data via a
regular expression, it could cause Ruby to enter an infinite-loop and
crash. (CVE-2008-3443)

Users of ruby should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00f043d8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07e43e5f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2f64884"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/22");
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
if (rpm_check(release:"CentOS-3", reference:"irb-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-devel-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-docs-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-libs-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-mode-1.6.8-13.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ruby-tcltk-1.6.8-13.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");