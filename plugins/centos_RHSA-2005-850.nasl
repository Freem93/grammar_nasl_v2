#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:850 and 
# CentOS Errata and Security Advisory 2005:850 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21875);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2933");
  script_bugtraq_id(15009);
  script_osvdb_id(19856);
  script_xref(name:"RHSA", value:"2005:850");

  script_name(english:"CentOS 3 : imap (CESA-2005:850)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated imap package that fixes a buffer overflow issue is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The imap package provides server daemons for both the IMAP (Internet
Message Access Protocol) and POP (Post Office Protocol) mail access
protocols.

A buffer overflow flaw was discovered in the way the c-client library
parses user-supplied mailboxes. If an authenticated user requests a
specially crafted mailbox name, it may be possible to execute
arbitrary code on a server that uses the library. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2933 to this issue.

All users of imap should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012451.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbc68901"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012452.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03d10dcc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?911a2903"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected imap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"imap-2002d-12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"imap-devel-2002d-12")) flag++;
if (rpm_check(release:"CentOS-3", reference:"imap-utils-2002d-12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
