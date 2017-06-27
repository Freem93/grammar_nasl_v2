#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:788 and 
# CentOS Errata and Security Advisory 2005:788 respectively.
#

include("compat.inc");

if (description)
{
  script_id(23983);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2629", "CVE-2005-2710", "CVE-2005-2922");
  script_osvdb_id(19695, 19696);
  script_xref(name:"RHSA", value:"2005:788");

  script_name(english:"CentOS 4 : Helix / Player (CESA-2005:788)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated HelixPlayer package that fixes a string format issue is now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

HelixPlayer is a media player.

A format string bug was discovered in the way HelixPlayer processes
RealPix (.rp) files. It is possible for a malformed RealPix file to
execute arbitrary code as the user running HelixPlayer. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2710 to this issue.

All users of HelixPlayer are advised to upgrade to this updated
package, which contains HelixPlayer version 10.0.6 and is not
vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e7a6ff2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012208.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eec3cbb9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected helix and / or player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/08");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/26");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"HelixPlayer-1.0.6-0.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"HelixPlayer-1.0.6-0.EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
