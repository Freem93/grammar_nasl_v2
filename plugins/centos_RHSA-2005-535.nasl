#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:535 and 
# CentOS Errata and Security Advisory 2005:535 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21838);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1993");
  script_bugtraq_id(13993);
  script_osvdb_id(17396);
  script_xref(name:"RHSA", value:"2005:535");

  script_name(english:"CentOS 3 / 4 : sudo (CESA-2005:535)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package is available that fixes a race condition in
sudo's pathname validation.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root with logging.

A race condition bug was found in the way sudo handles pathnames. It
is possible that a local user with limited sudo access could create a
race condition that would allow the execution of arbitrary commands as
the root user. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1993 to this issue.

Users of sudo should update to this updated package, which contains a
backported patch and is not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011905.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9739763b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fcdd299"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56245578"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011908.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c77bf6ea"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e945fe9e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecbc0fab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/21");
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
if (rpm_check(release:"CentOS-3", reference:"sudo-1.6.7p5-1.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sudo-1.6.7p5-30.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
