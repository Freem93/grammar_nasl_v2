#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:365 and 
# CentOS Errata and Security Advisory 2005:365 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21811);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");
  script_osvdb_id(15276, 15277, 15278, 15279, 15280);
  script_xref(name:"RHSA", value:"2005:365");

  script_name(english:"CentOS 3 / 4 : gaim (CESA-2005:365)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gaim package that fixes multiple denial of service issues
is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Gaim application is a multi-protocol instant messaging client.

A buffer overflow bug was found in the way gaim escapes HTML. It is
possible that a remote attacker could send a specially crafted message
to a Gaim client, causing it to crash. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-0965
to this issue.

A bug was found in several of gaim's IRC processing functions. These
functions fail to properly remove various markup tags within an IRC
message. It is possible that a remote attacker could send a specially
crafted message to a Gaim client connected to an IRC server, causing
it to crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0966 to this issue.

A bug was found in gaim's Jabber message parser. It is possible for a
remote Jabber user to send a specially crafted message to a Gaim
client, causing it to crash. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0967 to this
issue.

In addition to these denial of service issues, multiple minor upstream
bugfixes are included in this update.

Users of Gaim are advised to upgrade to this updated package which
contains Gaim version 1.2.1 and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a17f738"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011558.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?594c9881"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011559.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?015463fc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e00c22f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b0b4a4a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gaim package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/01");
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
if (rpm_check(release:"CentOS-3", reference:"gaim-1.2.1-4.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gaim-1.2.1-4.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
