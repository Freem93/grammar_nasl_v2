#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0515 and 
# CentOS Errata and Security Advisory 2006:0515 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21903);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-1173");
  script_osvdb_id(26197);
  script_xref(name:"RHSA", value:"2006:0515");

  script_name(english:"CentOS 3 / 4 : sendmail (CESA-2006:0515)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages are now available to fix a denial of service
security issue.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 27 June 2006] The sendmail-docs packages for Red Hat
Enterprise Linux 3 have been updated to the correct version and
release.

Sendmail is a Mail Transport Agent (MTA) used to send mail between
machines.

A flaw in the handling of multi-part MIME messages was discovered in
Sendmail. A remote attacker could create a carefully crafted message
that could crash the sendmail process during delivery (CVE-2006-1173).
By default on Red Hat Enterprise Linux, Sendmail is configured to only
accept connections from the local host. Therefore, only users who have
configured Sendmail to listen to remote hosts would be remotely
vulnerable to this issue.

Users of Sendmail are advised to upgrade to these erratum packages,
which contain a backported patch from the Sendmail team to correct
this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7364f1b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012965.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56ea27ff"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47593014"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b02fc429"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bd2c3fc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012971.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ab1acc7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sendmail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/07");
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
if (rpm_check(release:"CentOS-3", reference:"sendmail-8.12.11-4.RHEL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-cf-8.12.11-4.RHEL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-devel-8.12.11-4.RHEL3.6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-doc-8.12.11-4.RHEL3.6")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sendmail-8.13.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-cf-8.13.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-devel-8.13.1-3.RHEL4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-doc-8.13.1-3.RHEL4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
