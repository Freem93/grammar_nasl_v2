#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:517 and 
# CentOS Errata and Security Advisory 2005:517 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21944);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/19 14:21:00 $");

  script_cve_id("CVE-2005-1766");
  script_bugtraq_id(14048);
  script_osvdb_id(17575);
  script_xref(name:"RHSA", value:"2005:517");

  script_name(english:"CentOS 4 : HelixPlayer (CESA-2005:517)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated HelixPlayer package that fixes a buffer overflow issue is
now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

HelixPlayer is a media player.

A buffer overflow bug was found in the way HelixPlayer processes SMIL
files. An attacker could create a specially crafted SMIL file, which
when combined with a malicious web server, could execute arbitrary
code when opened by a user. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-1766 to this
issue.

All users of HelixPlayer are advised to upgrade to this updated
package, which contains HelixPlayer version 10.0.5 and is not
vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d980d495"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a9ff1da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected helixplayer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/23");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"HelixPlayer-1.0.5-0.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"HelixPlayer-1.0.5-0.EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
