#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2378 and 
# CentOS Errata and Security Advisory 2015:2378 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87154);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2015-3455");
  script_osvdb_id(121513);
  script_xref(name:"RHSA", value:"2015:2378");

  script_name(english:"CentOS 7 : squid (CESA-2015:2378)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated squid packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Squid is a high-performance proxy caching server for web clients,
supporting FTP, Gopher, and HTTP data objects.

It was found that Squid configured with client-first SSL-bump did not
correctly validate X.509 server certificate host name fields. A
man-in-the-middle attacker could use this flaw to spoof a Squid server
using a specially crafted X.509 certificate. (CVE-2015-3455)

This update fixes the following bugs :

* Previously, the squid process did not handle file descriptors
correctly when receiving Simple Network Management Protocol (SNMP)
requests. As a consequence, the process gradually accumulated open
file descriptors. This bug has been fixed and squid now handles SNMP
requests correctly, closing file descriptors when necessary.
(BZ#1198778)

* Under high system load, the squid process sometimes terminated
unexpectedly with a segmentation fault during reboot. This update
provides better memory handling during reboot, thus fixing this bug.
(BZ#1225640)

Users of squid are advised to upgrade to these updated packages, which
fix these bugs. After installing this update, the squid service will
be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ac5ab6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid-sysvinit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-3.3.8-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"squid-sysvinit-3.3.8-26.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
