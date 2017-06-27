#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:880 and 
# CentOS Errata and Security Advisory 2005:880 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21974);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 14:21:00 $");

  script_cve_id("CVE-2005-3962");
  script_bugtraq_id(15629);
  script_osvdb_id(21345, 22255);
  script_xref(name:"RHSA", value:"2005:880");

  script_name(english:"CentOS 4 : perl (CESA-2005:880)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix security issues and bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

An integer overflow bug was found in Perl's format string processor.
It is possible for an attacker to cause perl to crash or execute
arbitrary code if the attacker is able to process a malicious format
string. This issue is only exploitable through a script which passes
arbitrary untrusted strings to the format string processor. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-3962
to this issue.

Users of Perl are advised to upgrade to these updated packages, which
contain backported patches to correct these issues as well as fixes
for several bugs."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9803be7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8979ff2c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90d0f868"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"perl-5.8.5-24.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"perl-suidperl-5.8.5-24.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
