#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:745 and 
# CentOS Errata and Security Advisory 2005:745 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21959);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2368");
  script_osvdb_id(18266);
  script_xref(name:"RHSA", value:"2005:745");

  script_name(english:"CentOS 3 / 4 : vim (CESA-2005:745)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vim packages that fix a security issue are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

VIM (VIsual editor iMproved) is a version of the vi editor.

A bug was found in the way VIM processes modelines. If a user with
modelines enabled opens a text file with a carefully crafted modeline,
arbitrary commands may be executed as the user running VIM. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-2368 to this issue.

Users of VIM are advised to upgrade to these updated packages, which
resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dd6771b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a96ef9d2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4e7bf89"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012090.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32137c76"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?270ca8f9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bb34eae"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/25");
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
if (rpm_check(release:"CentOS-3", reference:"vim-X11-6.3.046-0.30E.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-common-6.3.046-0.30E.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-enhanced-6.3.046-0.30E.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"vim-minimal-6.3.046-0.30E.4")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-X11-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-X11-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-X11-6.3.046-0.40E.7.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-common-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-common-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-common-6.3.046-0.40E.7.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-enhanced-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-enhanced-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-enhanced-6.3.046-0.40E.7.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"vim-minimal-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"vim-minimal-6.3.046-0.40E.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"vim-minimal-6.3.046-0.40E.7.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
