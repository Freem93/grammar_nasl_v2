#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1911 and 
# CentOS Errata and Security Advisory 2014:1911 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79642);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-8080", "CVE-2014-8090");
  script_bugtraq_id(70935, 71230);
  script_osvdb_id(113747, 114641);
  script_xref(name:"RHSA", value:"2014:1911");

  script_name(english:"CentOS 6 : ruby (CESA-2014:1911)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

Multiple denial of service flaws were found in the way the Ruby REXML
XML parser performed expansion of parameter entities. A specially
crafted XML document could cause REXML to use an excessive amount of
CPU and memory. (CVE-2014-8080, CVE-2014-8090)

The CVE-2014-8090 issue was discovered by Red Hat Product Security.

All ruby users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
instances of Ruby need to be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020791.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00c915e0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ruby-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-devel-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-docs-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-irb-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-libs-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-rdoc-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-ri-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-static-1.8.7.374-3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-tcltk-1.8.7.374-3.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
