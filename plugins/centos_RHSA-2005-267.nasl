#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:267 and 
# CentOS Errata and Security Advisory 2005:267 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21922);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2549", "CVE-2005-2550");
  script_bugtraq_id(14532);
  script_osvdb_id(18687, 18688, 18689, 18690);
  script_xref(name:"RHSA", value:"2005:267");

  script_name(english:"CentOS 3 / 4 : Evolution (CESA-2005:267)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix a format string issue are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Evolution is the GNOME collection of personal information management
(PIM) tools.

A format string bug was found in Evolution. If a user tries to save a
carefully crafted meeting or appointment, arbitrary code may be
executed as the user running Evolution. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2005-2550 to this issue.

Additionally, several other format string bugs were found in
Evolution. If a user views a malicious vCard, connects to a malicious
LDAP server, or displays a task list from a malicious remote server,
arbitrary code may be executed as the user running Evolution. The
Common Vulnerabilities and Exposures project has assigned the name
CVE-2005-2549 to this issue. Please note that this issue only affects
Red Hat Enterprise Linux 4.

All users of Evolution should upgrade to these updated packages, which
contain a backported patch which resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06c4cabb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63279677"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e54875ad"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68421fa9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012105.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b40d470"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7887481"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/10");
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
if (rpm_check(release:"CentOS-3", reference:"evolution-1.4.5-16")) flag++;
if (rpm_check(release:"CentOS-3", reference:"evolution-devel-1.4.5-16")) flag++;

if (rpm_check(release:"CentOS-4", reference:"evolution-2.0.2-16.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-devel-2.0.2-16.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
