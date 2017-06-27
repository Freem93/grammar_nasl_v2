#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:021 and 
# CentOS Errata and Security Advisory 2005:021 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21795);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886", "CVE-2004-1307", "CVE-2004-1308");
  script_osvdb_id(10750, 10751, 10909);
  script_xref(name:"RHSA", value:"2005:021");

  script_name(english:"CentOS 3 : kdegraphics (CESA-2005:021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that resolve multiple security issues in
kfax are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team

The kdegraphics package contains graphics applications for the K
Desktop Environment.

During a source code audit, Chris Evans discovered a number of integer
overflow bugs that affect libtiff. The kfax application contains a
copy of the libtiff code used for parsing TIFF files and is therefore
affected by these bugs. An attacker who has the ability to trick a
user into opening a malicious TIFF file could cause kfax to crash or
possibly execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the names CVE-2004-0886
and CVE-2004-0804 to these issues.

Additionally, a number of buffer overflow bugs that affect libtiff
have been found. The kfax application contains a copy of the libtiff
code used for parsing TIFF files and is therefore affected by these
bugs. An attacker who has the ability to trick a user into opening a
malicious TIFF file could cause kfax to crash or possibly execute
arbitrary code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0803 to this issue.

Users of kfax should upgrade to these updated packages, which contain
backported patches and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d567f190"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50892425"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78180e28"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/14");
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
if (rpm_check(release:"CentOS-3", reference:"kdegraphics-3.1.3-3.7")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kdegraphics-devel-3.1.3-3.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
