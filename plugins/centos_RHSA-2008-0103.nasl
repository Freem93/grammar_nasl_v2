#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0103 and 
# CentOS Errata and Security Advisory 2008:0103 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(30220);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593");
  script_bugtraq_id(24293, 27406, 27683);
  script_xref(name:"RHSA", value:"2008:0103");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2008:0103)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processed certain
malformed web content. A webpage containing malicious content could
cause Firefox to crash, or potentially execute arbitrary code as the
user running Firefox. (CVE-2008-0412, CVE-2008-0413, CVE-2008-0415,
CVE-2008-0419)

Several flaws were found in the way Firefox displayed malformed web
content. A webpage containing specially crafted content could trick a
user into surrendering sensitive information. (CVE-2008-0591,
CVE-2008-0593)

A flaw was found in the way Firefox stored password data. If a user
saves login information for a malicious website, it could be possible
to corrupt the password database, preventing the user from properly
accessing saved password data. (CVE-2008-0417)

A flaw was found in the way Firefox handles certain chrome URLs. If a
user has certain extensions installed, it could allow a malicious
website to steal sensitive session data. Note: this flaw does not
affect a default installation of Firefox. (CVE-2008-0418)

A flaw was found in the way Firefox saves certain text files. If a
website offers a file of type 'plain/text', rather than 'text/plain',
Firefox will not show future 'text/plain' content to the user in the
browser, forcing them to save those files locally to view the content.
(CVE-2008-0592)

Users of firefox are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42514ffc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?084dd855"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e3369ef"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?306a0966"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73390fe9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.10.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-9.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-9.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
