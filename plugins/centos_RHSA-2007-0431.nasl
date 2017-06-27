#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0431 and 
# CentOS Errata and Security Advisory 2007:0431 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25497);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2006-1174");
  script_osvdb_id(25848);
  script_xref(name:"RHSA", value:"2007:0431");

  script_name(english:"CentOS 3 : shadow-utils (CESA-2007:0431)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated shadow-utils package that fixes a security issue and
several bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The shadow-utils package includes the necessary programs for
converting UNIX password files to the shadow password format, as well
as programs for managing user and group accounts.

A flaw was found in the useradd tool in shadow-utils. A new user's
mailbox, when created, could have random permissions for a short
period. This could allow a local attacker to read or modify the
mailbox. (CVE-2006-1174)

This update also fixes the following bugs :

* shadow-utils debuginfo package was empty.

* chage.1 and chage -l gave incorrect information about sp_inact.

All users of shadow-utils are advised to upgrade to this updated
package, which contains backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88787bd4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efab9fc3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013913.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be5af716"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shadow-utils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:shadow-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/23");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"shadow-utils-4.0.3-29.RHEL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
