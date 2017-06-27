#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:743 and 
# CentOS Errata and Security Advisory 2005:743 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21958);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2471");
  script_bugtraq_id(14379, 15128);
  script_osvdb_id(18253);
  script_xref(name:"RHSA", value:"2005:743");

  script_name(english:"CentOS 3 / 4 : netpbm (CESA-2005:743)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated netpbm packages that fix a security issue are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The netpbm package contains a library of functions that support
programs for handling various graphics file formats, including .pbm
(portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
.ppm (portable pixmaps) and others.

A bug was found in the way netpbm converts PostScript files into PBM,
PGM or PPM files. An attacker could create a carefully crafted
PostScript file in such a way that it could execute arbitrary commands
when the file is processed by a victim using pstopnm. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-2471
to this issue.

All users of netpbm should upgrade to the updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5745659f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?031a2b10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?475e393f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012082.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fb3ecaa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b80f97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-August/012089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fd693eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected netpbm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:netpbm-progs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/24");
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
if (rpm_check(release:"CentOS-3", reference:"netpbm-9.24-11.30.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-devel-9.24-11.30.2")) flag++;
if (rpm_check(release:"CentOS-3", reference:"netpbm-progs-9.24-11.30.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"netpbm-10.25-2.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"netpbm-devel-10.25-2.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"netpbm-progs-10.25-2.EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
