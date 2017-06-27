#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:878 and 
# CentOS Errata and Security Advisory 2005:878 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21876);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3628");
  script_bugtraq_id(15721, 15725, 15726, 15727);
  script_osvdb_id(21462, 21463);
  script_xref(name:"RHSA", value:"2005:878");

  script_name(english:"CentOS 3 / 4 : cups (CESA-2005:878)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated CUPS packages that fix multiple security issues are now
available for Red Hat Enterprise Linux.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX(R) operating systems.

Several flaws were discovered in the way CUPS processes PDF files. An
attacker could construct a carefully crafted PDF file that could cause
CUPS to crash or possibly execute arbitrary code when opened. The
Common Vulnerabilities and Exposures project assigned the names
CVE-2005-3191, CVE-2005-3192, and CVE-2005-3193 to these issues.

All users of CUPS should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19bfe103"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33ab75b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012488.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9879786"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012492.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4605e3ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa1e1954"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-December/012532.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13038c43"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/05");
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
if (rpm_check(release:"CentOS-3", reference:"cups-1.1.17-13.3.34")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-devel-1.1.17-13.3.34")) flag++;
if (rpm_check(release:"CentOS-3", reference:"cups-libs-1.1.17-13.3.34")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cups-1.1.22-0.rc1.9.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-devel-1.1.22-0.rc1.9.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cups-libs-1.1.22-0.rc1.9.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
