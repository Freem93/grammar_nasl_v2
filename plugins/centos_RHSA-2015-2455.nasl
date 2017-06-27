#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2455 and 
# CentOS Errata and Security Advisory 2015:2455 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87159);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2014-8602");
  script_osvdb_id(115667);
  script_xref(name:"RHSA", value:"2015:2455");

  script_name(english:"CentOS 7 : unbound (CESA-2015:2455)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated unbound packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The unbound packages provide a validating, recursive, and caching DNS
or DNSSEC resolver.

A denial of service flaw was found in unbound that an attacker could
use to trick the unbound resolver into following an endless loop of
delegations, consuming an excessive amount of resources.
(CVE-2014-8602)

This update also fixes the following bugs :

* Prior to this update, there was a mistake in the time configuration
in the cron job invoking unbound-anchor to update the root zone key.
Consequently, unbound-anchor was invoked once a month instead of every
day, thus not complying with RFC 5011. The cron job has been replaced
with a systemd timer unit that is invoked on a daily basis. Now, the
root zone key validity is checked daily at a random time within a
24-hour window, and compliance with RFC 5011 is ensured. (BZ#1180267)

* Previously, the unbound packages were installing their configuration
file for the systemd-tmpfiles utility into the /etc/tmpfiles.d/
directory. As a consequence, changes to unbound made by the
administrator in /etc/tmpfiles.d/ could be overwritten on package
reinstallation or update. To fix this bug, unbound has been amended to
install the configuration file into the /usr/lib/tmpfiles.d/
directory. As a result, the system administrator's configuration in
/etc/tmpfiles.d/ is preserved, including any changes, on package
reinstallation or update. (BZ#1180995)

* The unbound server default configuration included validation of DNS
records using the DNSSEC Look-aside Validation (DLV) registry. The
Internet Systems Consortium (ISC) plans to deprecate the DLV registry
service as no longer needed, and unbound could execute unnecessary
steps. Therefore, the use of the DLV registry has been removed from
the unbound server default configuration. Now, unbound does not try to
perform DNS records validation using the DLV registry. (BZ#1223339)

All unbound users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-November/002657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe5d9135"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbound packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unbound-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unbound-python");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"unbound-1.4.20-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"unbound-devel-1.4.20-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"unbound-libs-1.4.20-26.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"unbound-python-1.4.20-26.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
