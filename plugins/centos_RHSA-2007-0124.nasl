#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0124 and 
# CentOS Errata and Security Advisory 2007:0124 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24878);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:16 $");

  script_cve_id("CVE-2007-1536");
  script_bugtraq_id(23021);
  script_osvdb_id(34285);
  script_xref(name:"RHSA", value:"2007:0124");

  script_name(english:"CentOS 4 : file (CESA-2007:0124)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated file package that fixes a security flaw is now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The file command is used to identify a particular file according to
the type of data contained by the file.

An integer underflow flaw was found in the file utility. An attacker
could create a carefully crafted file which, if examined by a victim
using the file utility, could lead to arbitrary code execution.
(CVE-2007-1536)

This issue did not affect the version of the file utility distributed
with Red Hat Enterprise Linux 2.1 or 3.

Users should upgrade to this erratum package, which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4e8ebbb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62cce865"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5ee55d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/08");
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
if (rpm_check(release:"CentOS-4", reference:"file-4.10-3.EL4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
