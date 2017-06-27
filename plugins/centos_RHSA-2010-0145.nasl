#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0145 and 
# CentOS Errata and Security Advisory 2010:0145 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45090);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2005-4268", "CVE-2010-0624");
  script_bugtraq_id(16057);
  script_osvdb_id(62857, 62950);
  script_xref(name:"RHSA", value:"2010:0145");

  script_name(english:"CentOS 3 : cpio (CESA-2010:0145)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cpio package that fixes two security issues is now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU cpio copies files into or out of a cpio or tar archive.

A heap-based buffer overflow flaw was found in the way cpio expanded
archive files. If a user were tricked into expanding a specially
crafted archive, it could cause the cpio executable to crash or
execute arbitrary code with the privileges of the user running cpio.
(CVE-2010-0624)

Red Hat would like to thank Jakob Lell for responsibly reporting the
CVE-2010-0624 issue.

A stack-based buffer overflow flaw was found in the way cpio expanded
large archive files. If a user expanded a specially crafted archive,
it could cause the cpio executable to crash. This issue only affected
64-bit platforms. (CVE-2005-4268)

Users of cpio are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2fd17d0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1be31897"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"cpio-2.5-6.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"cpio-2.5-6.RHEL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
