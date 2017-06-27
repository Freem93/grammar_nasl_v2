#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0863 and 
# CentOS Errata and Security Advisory 2008:0863 respectively.
#

include("compat.inc");

if (description)
{
  script_id(34062);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-2327");
  script_bugtraq_id(30832);
  script_xref(name:"RHSA", value:"2008:0863");

  script_name(english:"CentOS 3 : libtiff (CESA-2008:0863)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix a security issue are now available
for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Multiple uses of uninitialized values were discovered in libtiff's
Lempel-Ziv-Welch (LZW) compression algorithm decoder. An attacker
could create a carefully crafted LZW-encoded TIFF file that would
cause an application linked with libtiff to crash or, possibly,
execute arbitrary code. (CVE-2008-2327)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting this issue.

All libtiff users are advised to upgrade to these updated packages,
which contain backported patches to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015220.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b2e48d8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e6afd02"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-August/015223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6df7b6c0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libtiff-3.5.7-31.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libtiff-devel-3.5.7-31.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
