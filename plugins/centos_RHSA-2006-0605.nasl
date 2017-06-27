#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0605 and 
# CentOS Errata and Security Advisory 2006:0605 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22278);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2005-0155", "CVE-2006-3813");
  script_bugtraq_id(12426);
  script_osvdb_id(28229);
  script_xref(name:"RHSA", value:"2006:0605");

  script_name(english:"CentOS 4 : perl (CESA-2006:0605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix security a security issue are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

Kevin Finisterre discovered a flaw in sperl, the Perl setuid wrapper,
which can cause debugging information to be logged to arbitrary files.
By setting an environment variable, a local user could cause sperl to
create, as root, files with arbitrary filenames, or append the
debugging information to existing files. (CVE-2005-0155)

A fix for this issue was first included in the update RHSA-2005:103
released in February 2005. However the patch to correct this issue was
dropped from the update RHSA-2005:674 made in October 2005. This
regression has been assigned CVE-2006-3813.

Users of Perl are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a691f00"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0d9cca7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca24dc13"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/10");
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
if (rpm_check(release:"CentOS-4", reference:"perl-5.8.5-36.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"perl-suidperl-5.8.5-36.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
