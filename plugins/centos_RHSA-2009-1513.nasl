#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1513 and 
# CentOS Errata and Security Advisory 2009:1513 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43806);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2009-3608", "CVE-2009-3609");
  script_osvdb_id(59179, 59180, 59183);
  script_xref(name:"RHSA", value:"2009:1513");

  script_name(english:"CentOS 5 : cups (CESA-2009:1513)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems. The CUPS 'pdftops' filter converts
Portable Document Format (PDF) files to PostScript.

Two integer overflow flaws were found in the CUPS 'pdftops' filter. An
attacker could create a malicious PDF file that would cause 'pdftops'
to crash or, potentially, execute arbitrary code as the 'lp' user if
the file was printed. (CVE-2009-3608, CVE-2009-3609)

Red Hat would like to thank Chris Rohlf for reporting the
CVE-2009-3608 issue.

Users of cups are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
the update, the cupsd daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016218.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a41e5675"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016219.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba96b6d3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-11.el5_4.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-11.el5_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
