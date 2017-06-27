#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:346 and 
# CentOS Errata and Security Advisory 2005:346 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21925);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2499");
  script_xref(name:"RHSA", value:"2005:346");

  script_name(english:"CentOS 4 : slocate (CESA-2005:346)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated slocate package that fixes a denial of service and various
bugs is available.

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

  - File system type exclusions were processed only when
    starting updatedb and did not reflect file systems
    mounted while updatedb was running (for example,
    automounted file systems.)

  - File system type exclusions were ignored for file
    systems that were mounted to a path containing a
    symbolic link.

  - Databases created by slocate were owned by the slocate
    group even if they were created by regular users.

  - The default configuration excluded /mnt/floppy, but not
    /media.

  - The default configuration did not exclude nfs4 file
    systems.

Users of slocate are advised to upgrade to this updated package, which
contains backported patches and is not affected by these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0482330"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90608c7d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe1bdf7b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected slocate package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:slocate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (rpm_check(release:"CentOS-4", reference:"slocate-2.7-13.el4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
