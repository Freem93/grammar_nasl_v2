#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1471 and 
# CentOS Errata and Security Advisory 2009:1471 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43798);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2007-2027", "CVE-2008-7224");
  script_xref(name:"RHSA", value:"2009:1471");

  script_name(english:"CentOS 4 / 5 : elinks (CESA-2009:1471)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated elinks package that fixes two security issues is now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

ELinks is a text-based Web browser. ELinks does not display any
images, but it does support frames, tables, and most other HTML tags.

An off-by-one buffer overflow flaw was discovered in the way ELinks
handled its internal cache of string representations for HTML special
entities. A remote attacker could use this flaw to create a specially
crafted HTML file that would cause ELinks to crash or, possibly,
execute arbitrary code when rendered. (CVE-2008-7224)

It was discovered that ELinks tried to load translation files using
relative paths. A local attacker able to trick a victim into running
ELinks in a folder containing specially crafted translation files
could use this flaw to confuse the victim via incorrect translations,
or cause ELinks to crash and possibly execute arbitrary code via
embedded formatting sequences in translated messages. (CVE-2007-2027)

All ELinks users are advised to upgrade to this updated package, which
contains backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?451fa60f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?251a7a6a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?feb39c33"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5c459c5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(119, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elinks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/06");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"elinks-0.9.2-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"elinks-0.9.2-4.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"elinks-0.11.1-6.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
