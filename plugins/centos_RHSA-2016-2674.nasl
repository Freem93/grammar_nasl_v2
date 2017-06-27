#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2674 and 
# CentOS Errata and Security Advisory 2016:2674 respectively.
#

include("compat.inc");

if (description)
{
  script_id(94741);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 14:29:49 $");

  script_cve_id("CVE-2016-6313");
  script_osvdb_id(143068);
  script_xref(name:"RHSA", value:"2016:2674");

  script_name(english:"CentOS 6 / 7 : libgcrypt (CESA-2016:2674)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libgcrypt is now available for Red Hat Enterprise Linux
6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libgcrypt library provides general-purpose implementations of
various cryptographic algorithms.

Security Fix(es) :

* A design flaw was found in the libgcrypt PRNG (Pseudo-Random Number
Generator). An attacker able to obtain the first 580 bytes of the PRNG
output could predict the following 20 bytes. (CVE-2016-6313)

Red Hat would like to thank Felix Dorre and Vladimir Klebanov for
reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022141.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6dd1dc1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?171a51f2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgcrypt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libgcrypt-1.4.5-12.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libgcrypt-devel-1.4.5-12.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgcrypt-1.5.3-13.el7_3.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libgcrypt-devel-1.5.3-13.el7_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
