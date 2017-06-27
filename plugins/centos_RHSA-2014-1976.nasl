#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1976 and 
# CentOS Errata and Security Advisory 2014:1976 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79877);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_bugtraq_id(71558, 71588);
  script_osvdb_id(115601, 115602);
  script_xref(name:"RHSA", value:"2014:1976");

  script_name(english:"CentOS 7 : rpm (CESA-2014:1976)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpm packages that fix two security issues are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The RPM Package Manager (RPM) is a powerful command line driven
package management system capable of installing, uninstalling,
verifying, querying, and updating software packages. Each software
package consists of an archive of files along with information about
the package such as its version, description, and other information.

It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic
signature only after the temporary file has been written completely.
Under certain conditions, the system interprets the unverified
temporary file contents and extracts commands from it. This could
allow an attacker to modify signed RPM files in such a way that they
would execute code chosen by the attacker during package installation.
(CVE-2013-6435)

It was found that RPM could encounter an integer overflow, leading to
a stack-based buffer overflow, while parsing a crafted CPIO header in
the payload section of an RPM file. This could allow an attacker to
modify signed RPM files in such a way that they would execute code
chosen by the attacker during package installation. (CVE-2014-8118)

These issues were discovered by Florian Weimer of Red Hat Product
Security.

All rpm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications linked against the RPM library must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22402b11"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rpm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-build-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpm-sign");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-apidocs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-build-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-build-libs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-cron-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-devel-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-libs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-python-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpm-sign-4.11.1-18.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
