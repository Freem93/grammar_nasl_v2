#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0430 and 
# CentOS Errata and Security Advisory 2015:0430 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81895);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/18 15:21:15 $");

  script_cve_id("CVE-2014-0189");
  script_xref(name:"RHSA", value:"2015:0430");

  script_name(english:"CentOS 7 : virt-who (CESA-2015:0430)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated virt-who package that fixes one security issue, several
bugs, and adds various enhancements is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The virt-who package provides an agent that collects information about
virtual guests present in the system and reports them to the
subscription manager.

It was discovered that the /etc/sysconfig/virt-who configuration file,
which may contain hypervisor authentication credentials, was
world-readable. A local user could use this flaw to obtain
authentication credentials from this file. (CVE-2014-0189)

Red Hat would like to thank Sal Castiglione for reporting this issue.

The virt-who package has been upgraded to upstream version 0.11, which
provides a number of bug fixes and enhancements over the previous
version. The most notable bug fixes and enhancements include :

* Support for remote libvirt. * A fix for using encrypted passwords. *
Bug fixes and enhancements that increase the stability of virt-who.
(BZ#1122489)

This update also fixes the following bugs :

* Prior to this update, the virt-who agent failed to read the list of
virtual guests provided by the VDSM daemon. As a consequence, when in
VDSM mode, the virt-who agent was not able to send updates about
virtual guests to Subscription Asset Manager (SAM) and Red Hat
Satellite. With this update, the agent reads the list of guests when
in VDSM mode correctly and reports to SAM and Satellite as expected.
(BZ#1153405)

* Previously, virt-who used incorrect information when connecting to
Red Hat Satellite 5. Consequently, virt-who could not connect to Red
Hat Satellite 5 servers. The incorrect parameter has been corrected,
and virt-who can now successfully connect to Red Hat Satellite 5.
(BZ#1158859)

* Prior to this update, virt-who did not decode the hexadecimal
representation of a password before decrypting it. As a consequence,
the decrypted password did not match the original password, and
attempts to connect using the password failed. virt-who has been
updated to decode the encrypted password and, as a result, virt-who
now handles storing credentials using encrypted passwords as expected.
(BZ#1161607)

In addition, this update adds the following enhancement :

* With this update, virt-who is able to read the list of guests from a
remote libvirt hypervisor. (BZ#1127965)

Users of virt-who are advised to upgrade to this updated package,
which corrects these issues and adds these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-March/001834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e4e7bc0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt-who package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:virt-who");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"virt-who-0.11-5.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
