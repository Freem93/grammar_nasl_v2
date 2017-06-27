#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:410 and 
# CentOS Errata and Security Advisory 2005:410 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21819);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0372");
  script_osvdb_id(13669);
  script_xref(name:"RHSA", value:"2005:410");

  script_name(english:"CentOS 3 / 4 : gftp (CESA-2005:410)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gFTP package that fixes a directory traversal issue is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

gFTP is a multi-threaded FTP client for the X Window System.

A directory traversal bug was found in gFTP. If a user can be tricked
into downloading a file from a malicious ftp server, it is possible to
overwrite arbitrary files owned by the victim. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0372 to this issue.

Users of gftp should upgrade to this updated package, which contains a
backported fix for this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3458f618"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d32a3a4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e8a0c3f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c11cd1f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b651106"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea3dc1d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gftp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gftp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/10");
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
if (rpm_check(release:"CentOS-3", reference:"gftp-2.0.14-4")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gftp-2.0.17-5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
