#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1020 and 
# CentOS Errata and Security Advisory 2007:1020 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43660);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-4351");
  script_osvdb_id(42028);
  script_xref(name:"RHSA", value:"2007:1020");

  script_name(english:"CentOS 5 : cups (CESA-2007:1020)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix a security issue in the Internet
Printing Protocol (IPP) handling and correct some bugs are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

A flaw was found in the way CUPS handles certain Internet Printing
Protocol (IPP) tags. A remote attacker who is able to connect to the
IPP TCP port could send a malicious request causing the CUPS daemon to
crash, or potentially execute arbitrary code. Please note that the
default CUPS configuration does not allow remote hosts to connect to
the IPP TCP port. (CVE-2007-4351)

Red Hat would like to thank Alin Rad Pop for reporting this issue.

All CUPS users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue.

In addition, the following bugs were fixed :

* the CUPS service has been changed to start after sshd, to avoid
causing delays when logging in when the system is booted.

* the logrotate settings have been adjusted so they do not cause CUPS
to reload its configuration. This is to avoid re-printing the current
job, which could occur when it was a long-running job.

* a bug has been fixed in the handling of the If-Modified-Since: HTTP
header.

* in the LSPP configuration, labels for labeled jobs did not
line-wrap. This has been fixed.

* an access check in the LSPP configuration has been made more secure.

* the cups-lpd service no longer ignores the '-odocument-format=...'
option.

* a memory allocation bug has been fixed in cupsd.

* support for UNIX domain sockets authentication without passwords has
been added.

* in the LSPP configuration, a problem that could lead to cupsd
crashing has been fixed.

* the error handling in the initscript has been improved.

* The job-originating-host-name attribute was not correctly set for
jobs submitted via the cups-lpd service. This has been fixed.

* a problem with parsing IPv6 addresses in the configuration file has
been fixed.

* a problem that could lead to cupsd crashing when it failed to open a
'file:' URI has been fixed."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014356.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52b3c7dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cba2fdac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cups-1.2.4-11.14.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.2.4-11.14.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.2.4-11.14.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.2.4-11.14.el5_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
