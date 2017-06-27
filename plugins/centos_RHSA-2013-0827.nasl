#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0827 and 
# CentOS Errata and Security Advisory 2013:0827 respectively.
#

include("compat.inc");

if (description)
{
  script_id(66451);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-2053");
  script_bugtraq_id(59838);
  script_xref(name:"RHSA", value:"2013:0827");

  script_name(english:"CentOS 5 / 6 : openswan (CESA-2013:0827)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openswan packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks. When using Opportunistic Encryption, Openswan's pluto IKE
daemon requests DNS TXT records to obtain public RSA keys of itself
and its peers.

A buffer overflow flaw was found in Openswan. If Opportunistic
Encryption were enabled ('oe=yes' in '/etc/ipsec.conf') and an RSA key
configured, an attacker able to cause a system to perform a DNS lookup
for an attacker-controlled domain containing malicious records (such
as by sending an email that triggers a DKIM or SPF DNS record lookup)
could cause Openswan's pluto IKE daemon to crash or, potentially,
execute arbitrary code with root privileges. With 'oe= yes' but no RSA
key configured, the issue can only be triggered by attackers on the
local network who can control the reverse DNS entry of the target
system. Opportunistic Encryption is disabled by default.
(CVE-2013-2053)

This issue was discovered by Florian Weimer of the Red Hat Product
Security Team.

All users of openswan are advised to upgrade to these updated
packages, which contain backported patches to correct this issue.
After installing this update, the ipsec service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019731.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openswan-2.6.32-5.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openswan-doc-2.6.32-5.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"openswan-2.6.32-20.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openswan-doc-2.6.32-20.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
