#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1595 and 
# CentOS Errata and Security Advisory 2009:1595 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67076);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2820", "CVE-2009-3553", "CVE-2010-0302");
  script_bugtraq_id(36958);
  script_osvdb_id(60204);
  script_xref(name:"RHSA", value:"2009:1595");

  script_name(english:"CentOS 5 : cups (CESA-2009:1595)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 12th January 2010] The packages list in this erratum has been
updated to include missing i386 packages for Red Hat Enterprise Linux
Desktop and RHEL Desktop Workstation.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

A use-after-free flaw was found in the way CUPS handled references in
its file descriptors-handling interface. A remote attacker could, in a
specially crafted way, query for the list of current print jobs for a
specific printer, leading to a denial of service (cupsd crash).
(CVE-2009-3553)

Several cross-site scripting (XSS) flaws were found in the way the
CUPS web server interface processed HTML form content. If a remote
attacker could trick a local user who is logged into the CUPS web
interface into visiting a specially crafted HTML page, the attacker
could retrieve and potentially modify confidential CUPS administration
data. (CVE-2009-2820)

Red Hat would like to thank Aaron Sigel of Apple Product Security for
responsibly reporting the CVE-2009-2820 issue.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the cupsd daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016332.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8ac764f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016333.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?423b40d6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-11.el5_4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
