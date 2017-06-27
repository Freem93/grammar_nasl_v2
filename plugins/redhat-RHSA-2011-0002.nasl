#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0002. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63967);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/21 17:37:48 $");

  script_xref(name:"RHSA", value:"2011:0002");

  script_name(english:"RHEL 3 / 4 : redhat-release (EOL Notice) (RHSA-2011:0002)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the End Of Life notification for RHN Proxy Server 4.

On December 31st, 2010, per the life cycle support policy, the version
4 series of Satellite and Proxy products exited Production Phase 2
marking the end of their support by Red Hat. Please reference the
support policy here :

https://access.redhat.com/support/policy/updates/satellite/

Though we are committed to the December 31st date for beginning the
process of decommissioning Satellite and Proxy 4.x support, we
recognize that our customers have woven these products very deeply
into their processes and may need some time to migrate.

For migration purposes, please note the following dates: - December
31st, 2010 - Satellite and Proxy 4.x ceased to be supported. Official
support ended. Only Severity 1 issues and migration assistance will be
addressed. Satellite and Proxy will continue to operate, but all
customers are encouraged to migrate in a timely manner. - April 30th,
2011 - Satellite and Proxy 4.x active status will be terminated.
Satellite and Proxy version 4.x will enter an inactive state.
Satellite and Proxy communication to RHN Hosted will cease to function
(for example, the satellite-sync command will no longer work).

The Satellite Upgrade process starting point is outlined here :

http://docs.redhat.com/docs/en-US/Red_Hat_Network_Satellite/5.4/html/
Installation_Guide/s1-upgrades.html

How to proceed: - All Satellite and Proxy 4.x users must plan to
migrate to a newer version prior to April 30th, 2011. - If you have a
Technical Account Manager, contact that person immediately to discuss
migration plans. - Otherwise, contact support for assistance:
https://www.redhat.com/apps/support/ - Alternatively, Red Hat
Consulting can be engaged to assist with a smooth migration:
http://www.redhat.com/consulting/ More information on Red Hat
Consulting for Satellite can be found here :

http://www.redhat.com/f/pdf/consulting/RHNSatelliteImplementation-Broc
hure.pdf

It is critical to ensure you have a plan to migrate off of Satellite
and Proxy 4.x prior to April 30th, 2011."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/policy/updates/satellite/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.redhat.com/docs/en-US/Red_Hat_Network_Satellite/5.4/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/apps/support/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/consulting/"
  );
  # http://www.redhat.com/f/pdf/consulting/RHNSatelliteImplementation-Brochure.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b679f14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0002.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-auth-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-package-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-proxy-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL3", reference:"rhns-auth-daemon-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-broker-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-docs-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-management-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-package-manager-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-redirect-4.2.3-5")) flag++;
if (rpm_check(release:"RHEL3", reference:"rhns-proxy-tools-4.2.3-5")) flag++;

if (rpm_check(release:"RHEL4", reference:"rhns-auth-daemon-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-broker-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-docs-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-management-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-package-manager-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-redirect-4.2.3-6")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-proxy-tools-4.2.3-6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
