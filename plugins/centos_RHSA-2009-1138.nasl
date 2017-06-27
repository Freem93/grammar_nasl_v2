#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1138 and 
# CentOS Errata and Security Advisory 2009:1138 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43765);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2185", "CVE-2009-2661");
  script_bugtraq_id(35452);
  script_xref(name:"RHSA", value:"2009:1138");

  script_name(english:"CentOS 5 : openswan (CESA-2009:1138)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openswan packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks. Everything passing through the untrusted network is
encrypted by the IPsec gateway machine, and decrypted by the gateway
at the other end of the tunnel. The resulting tunnel is a virtual
private network (VPN).

Multiple insufficient input validation flaws were found in the way
Openswan's pluto IKE daemon processed some fields of X.509
certificates. A remote attacker could provide a specially crafted
X.509 certificate that would crash the pluto daemon. (CVE-2009-2185)

All users of openswan are advised to upgrade to these updated
packages, which contain a backported patch to correct these issues.
After installing this update, the ipsec service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?429a74af"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016022.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0672cd61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openswan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/02");
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
if (rpm_check(release:"CentOS-5", reference:"openswan-2.6.14-1.el5_3.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openswan-doc-2.6.14-1.el5_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
