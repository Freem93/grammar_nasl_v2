#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0346 and 
# CentOS Errata and Security Advisory 2011:0346 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53428);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_osvdb_id(72528, 72529, 72530);
  script_xref(name:"RHSA", value:"2011:0346");

  script_name(english:"CentOS 5 : openldap (CESA-2011:0346)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A flaw was found in the way OpenLDAP handled authentication failures
being passed from an OpenLDAP slave to the master. If OpenLDAP was
configured with a chain overlay and it forwarded authentication
failures, OpenLDAP would bind to the directory as an anonymous user
and return success, rather than return failure on the authenticated
bind. This could allow a user on a system that uses LDAP for
authentication to log into a directory-based account without knowing
the password. (CVE-2011-1024)

This update also fixes the following bug :

* Previously, multiple concurrent connections to an OpenLDAP server
could cause the slapd service to terminate unexpectedly with an
assertion error. This update adds mutexes to protect multiple threads
from accessing a structure with a connection, and the slapd service no
longer crashes. (BZ#677611)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ece3441e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017376.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eac1187d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"compat-openldap-2.3.43_2.2.29-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-2.3.43-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-clients-2.3.43-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-devel-2.3.43-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-2.3.43-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-overlays-2.3.43-12.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-sql-2.3.43-12.el5_6.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
