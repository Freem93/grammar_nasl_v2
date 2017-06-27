#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1651 and 
# CentOS Errata and Security Advisory 2009:1651 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43072);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/08/23 16:11:21 $");

  script_cve_id("CVE-2009-0159", "CVE-2009-3563");
  script_bugtraq_id(34481);
  script_osvdb_id(53593, 60847);
  script_xref(name:"RHSA", value:"2009:1651");

  script_name(english:"CentOS 3 : ntp (CESA-2009:1651)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ntp package that fixes two security issues is now available
for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

Robin Park and Dmitri Vinokurov discovered a flaw in the way ntpd
handled certain malformed NTP packets. ntpd logged information about
all such packets and replied with an NTP packet that was treated as
malformed when received by another ntpd. A remote attacker could use
this flaw to create an NTP packet reply loop between two ntpd servers
via a malformed packet with a spoofed source IP address and port,
causing ntpd on those servers to use excessive amounts of CPU time and
fill disk space with log messages. (CVE-2009-3563)

A buffer overflow flaw was found in the ntpq diagnostic command. A
malicious, remote server could send a specially crafted reply to an
ntpq request that could crash ntpq or, potentially, execute arbitrary
code with the privileges of the user running the ntpq command.
(CVE-2009-0159)

All ntp users are advised to upgrade to this updated package, which
contains backported patches to resolve these issues. After installing
the update, the ntpd daemon will restart automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8111c21"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?357dcf15"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"ntp-4.1.2-6.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"ntp-4.1.2-6.el3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
