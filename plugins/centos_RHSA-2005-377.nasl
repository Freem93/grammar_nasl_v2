#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:377 and 
# CentOS Errata and Security Advisory 2005:377 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21814);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-1772", "CVE-2004-1773", "CVE-2005-0990");
  script_osvdb_id(10231, 15260, 15375, 15376);
  script_xref(name:"RHSA", value:"2005:377");

  script_name(english:"CentOS 3 / 4 : sharutils (CESA-2005:377)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sharutils package is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The sharutils package contains a set of tools for encoding and
decoding packages of files in binary or text format.

A stack based overflow bug was found in the way shar handles the -o
option. If a user can be tricked into running a specially crafted
command, it could lead to arbitrary code execution. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-1772 to this issue. Please note that this issue does not
affect Red Hat Enterprise Linux 4.

Two buffer overflow bugs were found in sharutils. If an attacker can
place a malicious 'wc' command on a victim's machine, or trick a
victim into running a specially crafted command, it could lead to
arbitrary code execution. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-1773 to this
issue.

A bug was found in the way unshar creates temporary files. A local
user could use symlinks to overwrite arbitrary files the victim
running unshar has write access to. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0990
to this issue.

All users of sharutils should upgrade to this updated package, which
includes backported fixes to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?203e7211"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11ea0017"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd1f34ba"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sharutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sharutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/06");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"sharutils-4.2.1-16.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sharutils-4.2.1-22.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
