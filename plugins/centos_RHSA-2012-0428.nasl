#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0428 and 
# CentOS Errata and Security Advisory 2012:0428 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58504);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2011-4128", "CVE-2012-1569", "CVE-2012-1573");
  script_bugtraq_id(50609, 52667, 52668);
  script_osvdb_id(76961, 80258, 80259);
  script_xref(name:"RHSA", value:"2012:0428");

  script_name(english:"CentOS 5 : gnutls (CESA-2012:0428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix three security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS). GnuTLS includes
libtasn1, a library developed for ASN.1 (Abstract Syntax Notation One)
structures management that includes DER (Distinguished Encoding Rules)
encoding and decoding.

A flaw was found in the way GnuTLS decrypted malformed TLS records.
This could cause a TLS/SSL client or server to crash when processing a
specially crafted TLS record from a remote TLS/SSL connection peer.
(CVE-2012-1573)

A flaw was found in the way libtasn1 decoded DER data. An attacker
could create a carefully-crafted X.509 certificate that, when parsed
by an application that uses GnuTLS, could cause the application to
crash. (CVE-2012-1569)

A boundary error was found in the gnutls_session_get_data() function.
A malicious TLS/SSL server could use this flaw to crash a TLS/SSL
client or, possibly, execute arbitrary code as the client, if the
client passed a fixed-sized buffer to gnutls_session_get_data() before
checking the real size of the session data provided by the server.
(CVE-2011-4128)

Red Hat would like to thank Matthew Hall of Mu Dynamics for reporting
CVE-2012-1573 and CVE-2012-1569.

Users of GnuTLS are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all applications linked to the GnuTLS library
must be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-March/018529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c0b0fbf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/28");
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
if (rpm_check(release:"CentOS-5", reference:"gnutls-1.4.1-7.el5_8.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-devel-1.4.1-7.el5_8.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-utils-1.4.1-7.el5_8.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
