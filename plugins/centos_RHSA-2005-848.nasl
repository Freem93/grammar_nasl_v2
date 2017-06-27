#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:848 and 
# CentOS Errata and Security Advisory 2005:848 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21969);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2933");
  script_bugtraq_id(15009);
  script_osvdb_id(19856);
  script_xref(name:"RHSA", value:"2005:848");

  script_name(english:"CentOS 4 : libc-client (CESA-2005:848)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libc-client packages that fix a buffer overflow issue are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

C-client is a common API for accessing mailboxes.

A buffer overflow flaw was discovered in the way C-client parses
user-supplied mailboxes. If an authenticated user requests a specially
crafted mailbox name, it may be possible to execute arbitrary code on
a server that uses C-client to access mailboxes. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2933 to this issue.

All users of libc-client should upgrade to these updated packages,
which contain a backported patch that resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0008a508"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86f3db39"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f4de0e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libc-client packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libc-client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/04");
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
if (rpm_check(release:"CentOS-4", reference:"libc-client-2002e-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libc-client-devel-2002e-14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
