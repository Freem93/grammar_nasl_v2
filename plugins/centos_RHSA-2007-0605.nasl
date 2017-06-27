#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0605 and 
# CentOS Errata and Security Advisory 2007:0605 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25614);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3410");
  script_osvdb_id(37374, 38342);
  script_xref(name:"RHSA", value:"2007:0605");

  script_name(english:"CentOS 4 : HelixPlayer (CESA-2007:0605)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated HelixPlayer package that fixes a buffer overflow flaw is
now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

HelixPlayer is a media player.

A buffer overflow flaw was found in the way HelixPlayer processed
Synchronized Multimedia Integration Language (SMIL) files. It was
possible for a malformed SMIL file to execute arbitrary code with the
permissions of the user running HelixPlayer. (CVE-2007-3410)

All users of HelixPlayer are advised to upgrade to this updated
package, which contains a backported patch and is not vulnerable to
this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013994.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e6b8b19"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013995.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce655a86"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected helixplayer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/26");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"HelixPlayer-1.0.6-0.EL4.2.0.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"HelixPlayer-1.0.6-0.EL4.2.0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
