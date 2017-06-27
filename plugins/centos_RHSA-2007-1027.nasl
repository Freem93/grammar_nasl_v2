#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1027 and 
# CentOS Errata and Security Advisory 2007:1027 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36664);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:21:02 $");

  script_cve_id("CVE-2007-4033", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_osvdb_id(38698, 39541, 39542, 39543);
  script_xref(name:"RHSA", value:"2007:1027");

  script_name(english:"CentOS 4 : tetex (CESA-2007:1027)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (dvi) file as output.

Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause TeTeX to
crash or potentially execute arbitrary code when opened.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

A flaw was found in the t1lib library, used in the handling of Type 1
fonts. An attacker could create a malicious file that would cause
TeTeX to crash, or potentially execute arbitrary code when opened.
(CVE-2007-4033)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba433595"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014407.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbc49704"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014408.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?694e94e5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tetex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
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
if (rpm_check(release:"CentOS-4", reference:"tetex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-afm-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-doc-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-dvips-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-fonts-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-latex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"CentOS-4", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
