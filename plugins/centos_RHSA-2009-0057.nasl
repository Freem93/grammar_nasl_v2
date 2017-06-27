#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0057 and 
# CentOS Errata and Security Advisory 2009:0057 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35424);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:43:05 $");

  script_cve_id("CVE-2009-0030", "CVE-2009-1580");
  script_osvdb_id(51537);
  script_xref(name:"RHSA", value:"2009:0057");

  script_name(english:"CentOS 3 / 4 / 5 : squirrelmail (CESA-2009:0057)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes a security issue is now
available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SquirrelMail is an easy-to-configure, standards-based, webmail package
written in PHP. It includes built-in PHP support for the IMAP and SMTP
protocols, and pure HTML 4.0 page-rendering (with no JavaScript
required) for maximum browser-compatibility, strong MIME support,
address books, and folder manipulation.

The Red Hat SquirrelMail packages provided by the RHSA-2009:0010
advisory introduced a session handling flaw. Users who logged back
into SquirrelMail without restarting their web browsers were assigned
fixed session identifiers. A remote attacker could make use of that
flaw to hijack user sessions. (CVE-2009-0030)

SquirrelMail users should upgrade to this updated package, which
contains a patch to correct this issue. As well, all users who used
affected versions of SquirrelMail should review their preferences."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79dabb3c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015561.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afc082cb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015564.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a2ec087"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015565.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd6fca22"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a78745a7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015567.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9719c2f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/20");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"squirrelmail-1.4.8-9.el3.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"squirrelmail-1.4.8-9.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squirrelmail-1.4.8-5.el4.centos.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squirrelmail-1.4.8-5.el4.centos.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-5.el5.centos.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
