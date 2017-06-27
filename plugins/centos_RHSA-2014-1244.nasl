#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1244 and 
# CentOS Errata and Security Advisory 2014:1244 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77991);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id("CVE-2014-0591");
  script_bugtraq_id(64801);
  script_osvdb_id(101973);
  script_xref(name:"RHSA", value:"2014:1244");

  script_name(english:"CentOS 5 : bind97 (CESA-2014:1244)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind97 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. It contains a DNS server (named),
a resolver library with routines for applications to use when
interfacing with DNS, and tools for verifying that the DNS server is
operating correctly. These packages contain version 9.7 of the BIND
suite.

A denial of service flaw was found in the way BIND handled queries for
NSEC3-signed zones. A remote attacker could use this flaw against an
authoritative name server that served NCES3-signed zones by sending a
specially crafted query, which, when processed, would cause named to
crash. (CVE-2014-0591)

Note: The CVE-2014-0591 issue does not directly affect the version of
bind97 shipped in Red Hat Enterprise Linux 5. This issue is being
addressed however to assure it is not introduced in future builds of
bind97 (possibly built with a different compiler or C library
optimization).

This update also fixes the following bug :

* Previously, the bind97 initscript did not check for the existence of
the ROOTDIR variable when shutting down the named daemon. As a
consequence, some parts of the file system that are mounted when using
bind97 in a chroot environment were unmounted on daemon shut down,
even if bind97 was not running in a chroot environment. With this
update, the initscript has been fixed to check for the existence of
the ROOTDIR variable when unmounting some parts of the file system on
named daemon shut down. Now, when shutting down bind97 that is not
running in a chroot environment, no parts of the file system are
unmounted. (BZ#1059118)

All bind97 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the update, the BIND daemon (named) will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f05e486"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bind97 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind97-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"bind97-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-chroot-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-devel-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-libs-9.7.0-21.P2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind97-utils-9.7.0-21.P2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
