#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0207 and 
# CentOS Errata and Security Advisory 2006:0207 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21987);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0645");
  script_osvdb_id(23054);
  script_xref(name:"RHSA", value:"2006:0207");

  script_name(english:"CentOS 4 : gnutls (CESA-2006:0207)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix a security issue are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The GNU TLS Library provides support for cryptographic algorithms and
protocols such as TLS. GNU TLS includes Libtasn1, a library developed
for ASN.1 structures management that includes DER encoding and
decoding.

Several flaws were found in the way libtasn1 decodes DER. An attacker
could create a carefully crafted invalid X.509 certificate in such a
way that could trigger this flaw if parsed by an application that uses
GNU TLS. This could lead to a denial of service (application crash).
It is not certain if this issue could be escalated to allow arbitrary
code execution. The Common Vulnerabilities and Exposures project
assigned the name CVE-2006-0645 to this issue.

In Red Hat Enterprise Linux 4, the GNU TLS library is only used by the
Evolution client when connecting to an Exchange server or when
publishing calendar information to a WebDAV server.

Users are advised to upgrade to these updated packages, which contain
a backported patch from the GNU TLS maintainers to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50e739d4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76e0777a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-February/012636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83c3f8f6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"gnutls-1.0.20-3.2.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gnutls-devel-1.0.20-3.2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
