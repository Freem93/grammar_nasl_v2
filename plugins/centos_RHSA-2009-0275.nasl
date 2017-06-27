#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0275 and 
# CentOS Errata and Security Advisory 2009:0275 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35718);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:05 $");

  script_cve_id("CVE-2008-5005");
  script_xref(name:"RHSA", value:"2009:0275");

  script_name(english:"CentOS 3 : imap (CESA-2009:0275)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated imap packages to fix a security issue are now available for
Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The imap package provides server daemons for both the IMAP (Internet
Message Access Protocol) and POP (Post Office Protocol) mail access
protocols.

A buffer overflow flaw was discovered in the dmail and tmail mail
delivery utilities shipped with imap. If either of these utilities
were used as a mail delivery agent, a remote attacker could
potentially use this flaw to run arbitrary code as the targeted user
by sending a specially crafted mail message to the victim.
(CVE-2008-5005)

Users of imap should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a01cd6a0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83a60056"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa6513b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected imap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:imap-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"imap-2002d-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"imap-devel-2002d-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"imap-utils-2002d-15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
