#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1238 and 
# CentOS Errata and Security Advisory 2009:1238 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43778);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_bugtraq_id(36120);
  script_osvdb_id(57592, 57593);
  script_xref(name:"RHSA", value:"2009:1238");

  script_name(english:"CentOS 5 : dnsmasq (CESA-2009:1238)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated dnsmasq package that fixes two security issues is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Dnsmasq is a lightweight and easy to configure DNS forwarder and DHCP
server.

Core Security Technologies discovered a heap overflow flaw in dnsmasq
when the TFTP service is enabled (the '--enable-tftp' command line
option, or by enabling 'enable-tftp' in '/etc/dnsmasq.conf'). If the
configured tftp-root is sufficiently long, and a remote user sends a
request that sends a long file name, dnsmasq could crash or, possibly,
execute arbitrary code with the privileges of the dnsmasq service
(usually the unprivileged 'nobody' user). (CVE-2009-2957)

A NULL pointer dereference flaw was discovered in dnsmasq when the
TFTP service is enabled. This flaw could allow a malicious TFTP client
to crash the dnsmasq service. (CVE-2009-2958)

Note: The default tftp-root is '/var/ftpd', which is short enough to
make it difficult to exploit the CVE-2009-2957 issue; if a longer
directory name is used, arbitrary code execution may be possible. As
well, the dnsmasq package distributed by Red Hat does not have TFTP
support enabled by default.

All users of dnsmasq should upgrade to this updated package, which
contains a backported patch to correct these issues. After installing
the updated package, the dnsmasq service must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d01139e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee941f5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"dnsmasq-2.45-1.1.el5_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
