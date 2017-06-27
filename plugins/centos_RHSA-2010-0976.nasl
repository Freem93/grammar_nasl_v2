#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0976 and 
# CentOS Errata and Security Advisory 2010:0976 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51145);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/01/27 00:45:19 $");

  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762");
  script_bugtraq_id(45133, 45137);
  script_xref(name:"RHSA", value:"2010:0976");

  script_name(english:"CentOS 5 : bind (CESA-2010:0976)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bind packages that fix three security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Berkeley Internet Name Domain (BIND) is an implementation of the
Domain Name System (DNS) protocols. BIND includes a DNS server
(named); a resolver library (routines for applications to use when
interfacing with DNS); and tools for verifying that the DNS server is
operating correctly.

It was discovered that named did not invalidate previously cached
RRSIG records when adding an NCACHE record for the same entry to the
cache. A remote attacker allowed to send recursive DNS queries to
named could use this flaw to crash named. (CVE-2010-3613)

A flaw was found in the DNSSEC validation code in named. If named had
multiple trust anchors configured for a zone, a response to a request
for a record in that zone with a bad signature could cause named to
crash. (CVE-2010-3762)

It was discovered that, in certain cases, named did not properly
perform DNSSEC validation of an NS RRset for zones in the middle of a
DNSKEY algorithm rollover. This flaw could cause the validator to
incorrectly determine that the zone is insecure and not protected by
DNSSEC. (CVE-2010-3614)

All BIND users are advised to upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the update, the BIND daemon (named) will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-December/017209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0868f204"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-December/017210.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae2cba95"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"bind-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-chroot-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-devel-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libbind-devel-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-libs-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-sdb-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"bind-utils-9.3.6-4.P1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"caching-nameserver-9.3.6-4.P1.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
