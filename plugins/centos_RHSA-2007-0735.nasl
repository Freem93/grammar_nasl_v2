#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0735 and 
# CentOS Errata and Security Advisory 2007:0735 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25813);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3387");
  script_bugtraq_id(25124);
  script_osvdb_id(38120);
  script_xref(name:"RHSA", value:"2007:0735");

  script_name(english:"CentOS 3 / 4 : xpdf (CESA-2007:0735)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xpdf packages that fix a security issue in PDF handling are
now available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Xpdf is an X Window System-based viewer for Portable Document Format
(PDF) files.

Maurycy Prodeus discovered an integer overflow flaw in the processing
of PDF files. An attacker could create a malicious PDF file that would
cause Xpdf to crash or potentially execute arbitrary code when opened.
(CVE-2007-3387)

All users of Xpdf should upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3257b717"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5fb3f4f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6d978bb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014094.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c2ed236"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd5ef2ce"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014107.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1c54390"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/30");
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
if (rpm_check(release:"CentOS-3", reference:"xpdf-2.02-10.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"xpdf-3.00-12.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
