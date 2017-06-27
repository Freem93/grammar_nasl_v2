#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1797 and 
# CentOS Errata and Security Advisory 2011:1797 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57068);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2010-2761", "CVE-2010-4410", "CVE-2011-3597");
  script_bugtraq_id(44199, 45145, 49911);
  script_osvdb_id(69588, 69589, 75990);
  script_xref(name:"RHSA", value:"2011:1797");

  script_name(english:"CentOS 4 / 5 : perl (CESA-2011:1797)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated perl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming.

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)

It was found that the Perl CGI module used a hard-coded value for the
MIME boundary string in multipart/x-mixed-replace content. A remote
attacker could possibly use this flaw to conduct an HTTP response
splitting attack via a specially crafted HTTP request. (CVE-2010-2761)

A CRLF injection flaw was found in the way the Perl CGI module
processed a sequence of non-whitespace preceded by newline characters
in the header. A remote attacker could use this flaw to conduct an
HTTP response splitting attack via a specially crafted sequence of
characters provided to the CGI module. (CVE-2010-4410)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs
must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018306.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82c420e2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18097a3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018308.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?772f4b9b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f00d96e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/12");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-5.8.5-57.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-5.8.5-57.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-suidperl-5.8.5-57.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-suidperl-5.8.5-57.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"perl-5.8.8-32.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"perl-suidperl-5.8.8-32.el5_7.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
