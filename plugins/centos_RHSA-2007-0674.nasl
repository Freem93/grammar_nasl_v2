#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0674 and 
# CentOS Errata and Security Advisory 2007:0674 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25714);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3377", "CVE-2007-3409");
  script_bugtraq_id(24669);
  script_osvdb_id(37053, 37054);
  script_xref(name:"RHSA", value:"2007:0674");

  script_name(english:"CentOS 3 / 5 : perl-Net-DNS (CESA-2007:0674)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated perl-Net-DNS packages that correct two security issues are now
available for Red Hat Enterprise Linux 3 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Net::DNS is a collection of Perl modules that act as a Domain Name
System (DNS) resolver.

A flaw was found in the way Net::DNS generated the ID field in a DNS
query. This predictable ID field could be used by a remote attacker to
return invalid DNS data. (CVE-2007-3377)

A denial of service flaw was found in the way Net::DNS parsed certain
DNS requests. A malformed response to a DNS request could cause the
application using Net::DNS to crash or stop responding.
(CVE-2007-3409)

Users of Net::DNS should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014022.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a917dfd3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad40306b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bdd51a1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7cc4f5a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef9448e6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-net-dns package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Net-DNS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"perl-Net-DNS-0.31-4.el3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"perl-Net-DNS-0.59-3.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
