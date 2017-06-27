#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0723 and 
# CentOS Errata and Security Advisory 2007:0723 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25740);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3089", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_bugtraq_id(24946);
  script_osvdb_id(38000, 38001, 38002, 38010, 38015, 38016, 38017, 38024);
  script_xref(name:"RHSA", value:"2007:0723");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2007:0723)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way Thunderbird processed certain
malformed JavaScript code. A malicious HTML email message containing
JavaScript code could cause Thunderbird to crash or potentially
execute arbitrary code as the user running Thunderbird. JavaScript
support is disabled by default in Thunderbird; these issues are not
exploitable unless the user has enabled JavaScript. (CVE-2007-3089,
CVE-2007-3734, CVE-2007-3735, CVE-2007-3736, CVE-2007-3737,
CVE-2007-3738)

Users of Thunderbird are advised to upgrade to these erratum packages,
which contain backported patches that correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a34021e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b05638e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa245c11"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87fe57f0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014065.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e96d434d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-0.3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"thunderbird-1.5.0.12-0.3.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-0.3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-1.5.0.12-3.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
