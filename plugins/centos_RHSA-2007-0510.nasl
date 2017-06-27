#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0510 and 
# CentOS Errata and Security Advisory 2007:0510 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25577);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/03/19 14:21:01 $");

  script_cve_id("CVE-2007-3257");
  script_bugtraq_id(24567);
  script_osvdb_id(37489);
  script_xref(name:"RHSA", value:"2007:0510");

  script_name(english:"CentOS 5 : evolution-data-server (CESA-2007:0510)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution-data-server package that fixes a security bug are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The evolution-data-server package provides a unified backend for
programs that work with contacts, tasks, and calendar information.

A flaw was found in the way evolution-data-server processes certain
IMAP server messages. If a user can be tricked into connecting to a
malicious IMAP server it may be possible to execute arbitrary code as
the user running the evolution-data-server process. (CVE-2007-3257)

All users of evolution-data-server should upgrade to these updated
packages, which contain a backported patch which resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013986.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?061e0d51"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013987.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e49053c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"evolution-data-server-1.8.0-15.0.4.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"evolution-data-server-devel-1.8.0-15.0.4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
