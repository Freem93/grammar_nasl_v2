#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0899 and 
# CentOS Errata and Security Advisory 2012:0899 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59930);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2012-1164");
  script_bugtraq_id(52404);
  script_osvdb_id(80086);
  script_xref(name:"RHSA", value:"2012:0899");

  script_name(english:"CentOS 6 : openldap (CESA-2012:0899)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A denial of service flaw was found in the way the OpenLDAP server
daemon (slapd) processed certain search queries requesting only
attributes and no values. In certain configurations, a remote attacker
could issue a specially crafted LDAP search query that, when processed
by slapd, would cause slapd to crash due to an assertion failure.
(CVE-2012-1164)

These updated openldap packages include numerous bug fixes. Space
precludes documenting all of these changes in this advisory. Users are
directed to the Red Hat Enterprise Linux 6.3 Technical Notes for
information on the most significant of these changes.

Users of OpenLDAP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the OpenLDAP daemons will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018720.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8831f149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"openldap-2.4.23-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-clients-2.4.23-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-devel-2.4.23-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-2.4.23-26.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-sql-2.4.23-26.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
