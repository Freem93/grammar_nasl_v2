#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:345 and 
# CentOS Errata and Security Advisory 2005:345 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21808);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/28 23:40:39 $");

  script_cve_id("CVE-2005-2499");
  script_xref(name:"RHSA", value:"2005:345");

  script_name(english:"CentOS 3 : slocate (CESA-2005:345)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated slocate package that fixes a denial of service and various
bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Slocate is a security-enhanced version of locate. Like locate, slocate
searches through a central database (updated nightly) for files that
match a given pattern. Slocate allows you to quickly find files
anywhere on your system.

A bug was found in the way slocate scans the local filesystem. A
carefully prepared directory structure could cause updatedb's file
system scan to fail silently, resulting in an incomplete slocate
database. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2499 to this issue.

Additionally this update addresses the following issues :

  - Files with a size of 2 GB and larger were not entered
    into the slocate database.

  - File system type exclusions were processed only when
    starting updatedb and did not reflect file systems
    mounted while updatedb was running (for example,
    automounted file systems).

  - File system type exclusions were ignored for file
    systems that were mounted to a path containing a
    symbolic link.

  - Databases created by slocate were owned by the slocate
    group even if they were created by regular users.

Users of slocate are advised to upgrade to this updated package, which
contains backported patches and is not affected by these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012217.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?572098b6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73cd5a20"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b21db01"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected slocate package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slocate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"slocate-2.7-3.RHEL3.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
