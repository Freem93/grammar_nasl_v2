#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1547. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64069);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/21 17:37:49 $");

  script_xref(name:"RHSA", value:"2012:1547");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2012:1547)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the End Of Life notification for RHN Proxy Server 5 versions
released to run on Red Hat Enterprise Linux 4.

On December 1st, 2012, per the life cycle support policy, the
following versions of Satellite and Proxy products, released on Red
Hat Enterprise Linux 4, exited Production Phase 2 marking the end of
their support by Red Hat.

RHN Satellite & RHN Proxy: - 5.0 - 5.1 - 5.2 on Red Hat Enterprise
Linux 4 - 5.3 on Red Hat Enterprise Linux 4

Please reference the support policy here :

https://access.redhat.com/support/policy/updates/satellite/

Notes: 1) Red Hat will continue to support RHN Satellite and Proxy
versions 5.2 and 5.3 running on Red Hat Enterprise Linux 5. 2) All
versions of 5.0 and 5.1 are now EOL with this notice.

Though we are committed to the December 1st date for beginning the
process of decommissioning Satellite and Proxy support listed, we
recognize that our customers have woven these products very deeply
into their processes and may need some time to upgrade.

For upgrade purposes, please note the following dates :

* December 1st, 2012 - Satellite and Proxy support for listed versions
running on Red Hat Enterprise Linux 4, ceased to be supported.
Official support ended. Only Severity 1 issues and upgrade assistance
will be addressed. Satellite and Proxy will continue to operate, but
all customers are encouraged to upgrade in a timely manner.

* March 1st, 2013 - Satellite and Proxy versions listed - active
status will be terminated. The Satellite and Proxy versions listed
will enter an inactive state. This includes no longer generating nor
providing Satellite Certificates to customers requesting them for
these EOL product versions.

The overview for the Satellite Upgrade process starting point is
outlined here :

https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Network_Satelli
te/5.5/
html-single/Installation_Guide/index.html#chap-Installation_Guide-Upgr
ades

For detailed instructions on upgrading Red Hat Network Satellite,
please refer to the /etc/sysconfig/rhn/satellite-upgrade/README file.
This can be found within the rhn-upgrade package. Before proceeding,
it is important to read the complete details, contained within the
most current rhn-upgrade package README file.

As with all Satellite upgrades, please ensure that known good backups
are available, especially of the database.

How to proceed :

* All affected Satellite and Proxy users must plan to upgrade to a
newer version prior to March 1st, 2013.

* If you have a Technical Account Manager, contact that person
immediately to discuss upgrade plans.

* Otherwise, contact support for assistance:
https://www.redhat.com/support/

* Alternatively, Red Hat Consulting can be engaged to assist with a
smooth migration: http://www.redhat.com/consulting/

More information on Red Hat Consulting for Satellite can be found
here:
http://www.redhat.com/f/pdf/consulting/RHNSatelliteImplementation-Broc
hure.pdf

It is critical to ensure you have a plan to upgrade Satellite and
Proxy listed versions, prior to March 1st, 2013.

Listed versions of Satellite and Proxy for this notice are: - 5.0 -
5.1 - 5.2 on Red Hat Enterprise Linux 4 - 5.3 on Red Hat Enterprise
Linux 4"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Network_Satellite/5.5/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?998df6ca"
  );
  # http://www.redhat.com/f/pdf/consulting/RHNSatelliteImplementation-Brochure.pdf
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b679f14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1547.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected rhns-certs-tools and / or spacewalk-certs-tools
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhns-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-certs-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
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
if (rpm_check(release:"RHEL4", reference:"rhns-certs-tools-5.0.1-3.el4_8")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-certs-tools-5.1.1-3.el4")) flag++;
if (rpm_check(release:"RHEL4", reference:"rhns-certs-tools-5.2.0-5.el4")) flag++;
if (rpm_check(release:"RHEL4", reference:"spacewalk-certs-tools-0.5.5-7.el4sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
