#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1025 and 
# CentOS Errata and Security Advisory 2007:1025 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36452);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(39541, 39542, 39543);
  script_xref(name:"RHSA", value:"2007:1025");

  script_name(english:"CentOS 4 : gpdf (CESA-2007:1025)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gpdf packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

gpdf is a GNOME-based viewer for Portable Document Format (PDF) files.

Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause gpdf to
crash, or potentially execute arbitrary code when opened.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014372.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37436dd7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?867720d2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa94f55a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"gpdf-2.8.2-7.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
