#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0252 and 
# CentOS Errata and Security Advisory 2017:0252 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97026);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id("CVE-2016-7426", "CVE-2016-7429", "CVE-2016-7433", "CVE-2016-9310", "CVE-2016-9311");
  script_osvdb_id(147594, 147595, 147601, 147602, 147603);
  script_xref(name:"RHSA", value:"2017:0252");

  script_name(english:"CentOS 6 / 7 : ntp (CESA-2017:0252)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ntp is now available for Red Hat Enterprise Linux 6 and
Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with another referenced time source. These packages include the
ntpd service which continuously adjusts system time and utilities used
to query and configure the ntpd service.

Security Fix(es) :

* It was found that when ntp is configured with rate limiting for all
associations the limits are also applied to responses received from
its configured sources. A remote attacker who knows the sources can
cause a denial of service by preventing ntpd from accepting valid
responses from its sources. (CVE-2016-7426)

* A flaw was found in the control mode functionality of ntpd. A remote
attacker could send a crafted control mode packet which could lead to
information disclosure or result in DDoS amplification attacks.
(CVE-2016-9310)

* A flaw was found in the way ntpd implemented the trap service. A
remote attacker could send a specially crafted packet to cause a NULL
pointer dereference that will crash ntpd, resulting in a denial of
service. (CVE-2016-9311)

* A flaw was found in the way ntpd running on a host with multiple
network interfaces handled certain server responses. A remote attacker
could use this flaw which would cause ntpd to not synchronize with the
source. (CVE-2016-7429)

* A flaw was found in the way ntpd calculated the root delay. A remote
attacker could send a specially crafted spoofed packet to cause denial
of service or in some special cases even crash. (CVE-2016-7433)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4055a1b1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-February/022267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e59c649"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ntp-4.2.6p5-10.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-doc-4.2.6p5-10.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-perl-4.2.6p5-10.el6.centos.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntpdate-4.2.6p5-10.el6.centos.2")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-4.2.6p5-25.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-doc-4.2.6p5-25.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-25.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-25.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sntp-4.2.6p5-25.el7.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
