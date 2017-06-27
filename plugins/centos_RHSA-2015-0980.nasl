#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0980 and 
# CentOS Errata and Security Advisory 2015:0980 respectively.
#

include("compat.inc");

if (description)
{
  script_id(83375);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/08/11 17:08:42 $");

  script_cve_id("CVE-2015-1848", "CVE-2015-3983");
  script_bugtraq_id(74623, 74682);
  script_osvdb_id(122140);
  script_xref(name:"RHSA", value:"2015:0980");

  script_name(english:"CentOS 7 : pcs (CESA-2015:0980)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcs packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The pcs packages provide a command-line tool and a web UI to configure
and manage the Pacemaker and Corosync tools.

It was found that the pcs daemon did not sign cookies containing
session data that were sent to clients connecting via the pcsd web UI.
A remote attacker could use this flaw to forge cookies and bypass
authorization checks, possibly gaining elevated privileges in the pcsd
web UI. (CVE-2015-1848)

This issue was discovered by Tomas Jelinek of Red Hat.

This update also fixes the following bug :

* Previously, the Corosync tool allowed the two_node option and the
auto_tie_breaker option to exist in the corosync.conf file at the same
time. As a consequence, if both options were included,
auto_tie_breaker was silently ignored and the two_node fence race
decided which node would survive in the event of a communication
break. With this update, the pcs daemon has been fixed so that it does
not produce corosync.conf files with both two_node and
auto_tie_breaker included. In addition, if both two_node and
auto_tie_breaker are detected in corosync.conf, Corosync issues a
message at start-up and disables two_node mode. As a result,
auto_tie_breaker effectively overrides two_node mode if both options
are specified. (BZ#1205848)

All pcs users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the pcsd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021126.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-clufter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
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


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcs-0.9.137-13.el7_1.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-clufter-0.9.137-13.el7_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");