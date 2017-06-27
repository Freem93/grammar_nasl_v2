#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0167 and 
# CentOS Errata and Security Advisory 2010:0167 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45366);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/27 14:13:12 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0731");
  script_osvdb_id(59972, 63304);
  script_xref(name:"RHSA", value:"2010:0167");

  script_name(english:"CentOS 4 : gnutls (CESA-2010:0167)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix two security issues are now available
for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handled session
renegotiation. A man-in-the-middle attacker could use this flaw to
prefix arbitrary plain text to a client's session (for example, an
HTTPS connection to a website). This could force the server to process
an attacker's request as if authenticated using the victim's
credentials. This update addresses this flaw by implementing the TLS
Renegotiation Indication Extension, as defined in RFC 5746.
(CVE-2009-3555)

Refer to the following Knowledgebase article for additional details
about the CVE-2009-3555 flaw:
http://kbase.redhat.com/faq/docs/DOC-20491

A flaw was found in the way GnuTLS extracted serial numbers from X.509
certificates. On 64-bit big endian platforms, this flaw could cause
the certificate revocation list (CRL) check to be bypassed; cause
various GnuTLS utilities to crash; or, possibly, execute arbitrary
code. (CVE-2010-0731)

Users of GnuTLS are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all applications linked to the GnuTLS library
must be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016605.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb2579ee"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016606.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9e71204"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-1.0.20-4.el4_8.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-1.0.20-4.el4_8.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-devel-1.0.20-4.el4_8.7")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-devel-1.0.20-4.el4_8.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
