#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0967 and 
# CentOS Errata and Security Advisory 2007:0967 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43659);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/08/10 14:35:46 $");

  script_cve_id("CVE-2007-1659", "CVE-2007-1660");
  script_osvdb_id(40759, 40760, 40763, 40766);
  script_xref(name:"RHSA", value:"2007:0967");

  script_name(english:"CentOS 5 : pcre (CESA-2007:0967)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcre packages that correct two security flaws are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

PCRE is a Perl-compatible regular expression library.

Multiple flaws were found in the way pcre handles certain malformed
regular expressions. If an application linked against pcre, such as
Konqueror, parses a malicious regular expression, it may be possible
to run arbitrary code as the user running the application.
(CVE-2007-1659, CVE-2007-1660)

Users of pcre are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.

Red Hat would like to thank Tavis Ormandy and Will Drewry for properly
disclosing these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61d1d65d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014402.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03b79368"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"pcre-6.6-2.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pcre-devel-6.6-2.el5_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
