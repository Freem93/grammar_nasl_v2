#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0486 and 
# CentOS Errata and Security Advisory 2006:0486 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21901);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0052");
  script_osvdb_id(24367);
  script_xref(name:"RHSA", value:"2006:0486");

  script_name(english:"CentOS 3 / 4 : mailman (CESA-2006:0486)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mailman package that fixes a denial of service flaw is now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mailman is software to help manage email discussion lists.

A flaw was found in the way Mailman handles MIME multipart messages.
An attacker could send a carefully crafted MIME multipart email
message to a mailing list run by Mailman which would cause that
particular mailing list to stop working. (CVE-2006-0052)

Users of Mailman should upgrade to this updated package, which
contains backported patches to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85333a95"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a867c45f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84d97484"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd722a0b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?186d32dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?112b92ca"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/09");
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
if (rpm_check(release:"CentOS-3", reference:"mailman-2.1.5.1-25.rhel3.5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mailman-2.1.5.1-34.rhel4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
