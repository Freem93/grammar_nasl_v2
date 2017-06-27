#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1507 and 
# CentOS Errata and Security Advisory 2014:1507 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79183);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/12 17:31:56 $");

  script_cve_id("CVE-2012-0698");
  script_bugtraq_id(55459);
  script_xref(name:"RHSA", value:"2014:1507");

  script_name(english:"CentOS 6 : trousers (CESA-2014:1507)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated trousers packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

TrouSerS is an implementation of the Trusted Computing Group's
Software Stack (TSS) specification. You can use TrouSerS to write
applications that make use of your TPM hardware. TPM hardware can
create, store and use RSA keys securely (without ever being exposed in
memory), verify a platform's software state using cryptographic hashes
and more.

A flaw was found in the way tcsd, the daemon that manages Trusted
Computing resources, processed incoming TCP packets. A remote attacker
could send a specially crafted TCP packet that, when processed by
tcsd, could cause the daemon to crash. Note that by default tcsd
accepts requests on localhost only. (CVE-2012-0698)

Red Hat would like to thank Andrew Lutomirski for reporting this
issue.

The trousers package has been upgraded to upstream version 0.3.13,
which provides a number of bug fixes and enhancements over the
previous version, including corrected internal symbol names to avoid
collisions with other applications, fixed memory leaks, added IPv6
support, fixed buffer handling in tcsd, as well as changed the license
to BSD. (BZ#633584, BZ#1074634)

All trousers users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001389.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74670aee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected trousers packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:trousers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:trousers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:trousers-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"trousers-0.3.13-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"trousers-devel-0.3.13-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"trousers-static-0.3.13-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
