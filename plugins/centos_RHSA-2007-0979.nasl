#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0979 and 
# CentOS Errata and Security Advisory 2007:0979 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(27540);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(22688, 23668, 24725, 25142, 26132);
  script_osvdb_id(33809, 37994, 37995, 38026, 38033, 38034, 38035, 38043, 38044);
  script_xref(name:"RHSA", value:"2007:0979");

  script_name(english:"CentOS 4 / 5 : firefox (CESA-2007:0979)");
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

Several flaws were found in the way in which Firefox processed certain
malformed web content. A web page containing malicious content could
cause Firefox to crash or potentially execute arbitrary code as the
user running Firefox. (CVE-2007-5338, CVE-2007-5339, CVE-2007-5340)

Several flaws were found in the way in which Firefox displayed
malformed web content. A web page containing specially crafted content
could potentially trick a user into surrendering sensitive
information. (CVE-2007-1095, CVE-2007-3844, CVE-2007-3511,
CVE-2007-5334)

A flaw was found in the Firefox sftp protocol handler. A malicious web
page could access data from a remote sftp site, possibly stealing
sensitive user data. (CVE-2007-5337)

A request-splitting flaw was found in the way in which Firefox
generates a digest authentication request. If a user opened a
specially crafted URL, it was possible to perform cross-site scripting
attacks, web cache poisoning, or other, similar exploits.
(CVE-2007-2292)

All users of Firefox are advised to upgrade to these updated packages,
which contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014309.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5a9d1e9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e734316"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014313.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77a84aa7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014316.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?269771c9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014317.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?543b0268"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.12-0.7.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-1.5.0.12-6.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"firefox-devel-1.5.0.12-6.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
