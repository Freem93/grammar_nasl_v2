#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1482 and 
# CentOS Errata and Security Advisory 2015:1482 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85029);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/08/02 04:40:29 $");

  script_cve_id("CVE-2015-3245", "CVE-2015-3246");
  script_bugtraq_id(76021, 76022);
  script_osvdb_id(125263, 125264);
  script_xref(name:"RHSA", value:"2015:1482");
  script_xref(name:"IAVA", value:"2015-A-0179");

  script_name(english:"CentOS 6 : libuser (CESA-2015:1482)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libuser packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libuser library implements a standardized interface for
manipulating and administering user and group accounts. Sample
applications that are modeled after applications from the shadow
password suite (shadow-utils) are included in these packages.

Two flaws were found in the way the libuser library handled the
/etc/passwd file. A local attacker could use an application compiled
against libuser (for example, userhelper) to manipulate the
/etc/passwd file, which could result in a denial of service or
possibly allow the attacker to escalate their privileges to root.
(CVE-2015-3245, CVE-2015-3246)

Red Hat would like to thank Qualys for reporting these issues.

All libuser users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfdc11bc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuser-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuser-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

# Temp disable
exit(0, 'Temporarily disabled.');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libuser-0.56.13-8.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libuser-devel-0.56.13-8.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libuser-python-0.56.13-8.el6_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
