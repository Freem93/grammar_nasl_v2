#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1151 and 
# CentOS Errata and Security Advisory 2012:1151 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61464);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/01 13:30:47 $");

  script_cve_id("CVE-2012-2668");
  script_bugtraq_id(53823);
  script_osvdb_id(83078);
  script_xref(name:"RHSA", value:"2012:1151");

  script_name(english:"CentOS 6 : openldap (CESA-2012:1151)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

It was found that the OpenLDAP server daemon ignored olcTLSCipherSuite
settings. This resulted in the default cipher suite always being used,
which could lead to weaker than expected ciphers being accepted during
Transport Layer Security (TLS) negotiation with OpenLDAP clients.
(CVE-2012-2668)

This update also fixes the following bug :

* When the smbk5pwd overlay was enabled in an OpenLDAP server, and a
user changed their password, the Microsoft NT LAN Manager (NTLM) and
Microsoft LAN Manager (LM) hashes were not computed correctly. This
led to the sambaLMPassword and sambaNTPassword attributes being
updated with incorrect values, preventing the user logging in using a
Windows-based client or a Samba client.

With this update, the smbk5pwd overlay is linked against OpenSSL. As
such, the NTLM and LM hashes are computed correctly, and password
changes work as expected when using smbk5pwd. (BZ#844428)

Users of OpenLDAP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, the OpenLDAP daemons will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-August/018793.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50b8058f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"openldap-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-clients-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-devel-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-2.4.23-26.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openldap-servers-sql-2.4.23-26.el6_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
