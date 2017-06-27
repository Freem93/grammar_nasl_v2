#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0724 and 
# CentOS Errata and Security Advisory 2007:0724 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25741);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_bugtraq_id(24286, 24831, 24946);
  script_osvdb_id(38000, 38001, 38002, 38010, 38015, 38016, 38024, 38028);
  script_xref(name:"RHSA", value:"2007:0724");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2007:0724)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processed certain
malformed JavaScript code. A web page containing malicious JavaScript
code could cause Firefox to crash or potentially execute arbitrary
code as the user running Firefox. (CVE-2007-3734, CVE-2007-3735,
CVE-2007-3737, CVE-2007-3738)

Several content injection flaws were found in the way Firefox handled
certain JavaScript code. A web page containing malicious JavaScript
code could inject arbitrary content into other web pages.
(CVE-2007-3736, CVE-2007-3089)

A flaw was found in the way Firefox cached web pages on the local
disk. A malicious web page may be able to inject arbitrary HTML into a
browsing session if the user reloads a targeted site. (CVE-2007-3656)

Users of Firefox are advised to upgrade to these erratum packages,
which contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00b848a5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4db64733"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36fe7ace"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014062.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1702fcf2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef31e4e3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-3.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-3.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
