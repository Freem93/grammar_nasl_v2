#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:674 and 
# CentOS Errata and Security Advisory 2005:674 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67031);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/29 15:23:51 $");

  script_cve_id("CVE-2005-0448");
  script_bugtraq_id(12767);
  script_osvdb_id(14619);
  script_xref(name:"RHSA", value:"2005:674");

  script_name(english:"CentOS 4 : perl (CESA-2005:674)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix security issues and contain several bug
fixes are now available for Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

Paul Szabo discovered a bug in the way Perl's File::Path::rmtree
module removed directory trees. If a local user has write permissions
to a subdirectory within the tree being removed by File::Path::rmtree,
it is possible for them to create setuid binary files. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0448 to this issue.

This update also addresses the following issues :

-- Perl interpreter caused a segmentation fault when environment
changes occurred during runtime.

-- Code in lib/FindBin contained a regression that caused problems
with MRTG software package.

-- Perl incorrectly declared it provides an FCGI interface where it in
fact did not.

Users of Perl are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?617402de"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"perl-5.8.5-16.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"perl-suidperl-5.8.5-16.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
