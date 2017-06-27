#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1267 and 
# CentOS Errata and Security Advisory 2012:1267 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62104);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/08/31 14:21:47 $");

  script_cve_id("CVE-2012-4244");
  script_osvdb_id(85417);
  script_xref(name:"RHSA", value:"2012:1267");

  script_name(english:"CentOS 5 : bind (CESA-2012:1267)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

A flaw was found in the way BIND handled resource records with a large
RDATA value. A malicious owner of a DNS domain could use this flaw to
create specially crafted DNS resource records, that would cause a
recursive resolver or secondary server to exit unexpectedly with an
assertion failure. (CVE-2012-4244)

This update also fixes the following bug :

* The bind-chroot-admin script, executed when upgrading the
bind-chroot package, failed to correctly update the permissions of the
/var/named/chroot/etc/named.conf file. Depending on the permissions of
the file, this could have prevented named from starting after
installing package updates. With this update, bind-chroot-admin
correctly updates the permissions and ownership of the file.
(BZ#857056)

Users of bind are advised to upgrade to these updated packages, which
correct these issues. After installing the update, the BIND daemon
(named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62764a5e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:caching-nameserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-20.P1.el5_8.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-20.P1.el5_8.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
