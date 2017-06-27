#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1422 and 
# CentOS Errata and Security Advisory 2011:1422 respectively.
#

include("compat.inc");

if (description)
{
  script_id(56694);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2011-4073");
  script_bugtraq_id(50440);
  script_osvdb_id(76725);
  script_xref(name:"RHSA", value:"2011:1422");

  script_name(english:"CentOS 5 : openswan (CESA-2011:1422)");
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
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks.

A use-after-free flaw was found in the way Openswan's pluto IKE daemon
used cryptographic helpers. A remote, authenticated attacker could
send a specially crafted IKE packet that would crash the pluto daemon.
This issue only affected SMP (symmetric multiprocessing) systems that
have the cryptographic helpers enabled. The helpers are disabled by
default on Red Hat Enterprise Linux 5, but enabled by default on Red
Hat Enterprise Linux 6. (CVE-2011-4073)

Red Hat would like to thank the Openswan project for reporting this
issue. Upstream acknowledges Petar Tsankov, Mohammad Torabi Dashti and
David Basin of the information security group at ETH Zurich as the
original reporters.

All users of openswan are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing this update, the ipsec service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018143.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76e3b9b4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-November/018144.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17099ae4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"openswan-2.6.21-5.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openswan-doc-2.6.21-5.el5_7.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
