#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0574 and 
# CentOS Errata and Security Advisory 2017:0574 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97951);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/28 19:35:01 $");

  script_cve_id("CVE-2016-8610", "CVE-2017-5335", "CVE-2017-5336", "CVE-2017-5337");
  script_osvdb_id(146198, 149952, 149953, 149954);
  script_xref(name:"RHSA", value:"2017:0574");

  script_name(english:"CentOS 6 : gnutls (CESA-2017:0574)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for gnutls is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The gnutls packages provide the GNU Transport Layer Security (GnuTLS)
library, which implements cryptographic algorithms and protocols such
as SSL, TLS, and DTLS.

The following packages have been upgraded to a later upstream version:
gnutls (2.12.23). (BZ#1321112, BZ#1326073, BZ#1415682, BZ#1326389)

Security Fix(es) :

* A denial of service flaw was found in the way the TLS/SSL protocol
defined processing of ALERT packets during a connection handshake. A
remote attacker could use this flaw to make a TLS/SSL server consume
an excessive amount of CPU and fail to accept connections form other
clients. (CVE-2016-8610)

* Multiple flaws were found in the way gnutls processed OpenPGP
certificates. An attacker could create specially crafted OpenPGP
certificates which, when parsed by gnutls, would cause it to crash.
(CVE-2017-5335, CVE-2017-5336, CVE-2017-5337)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2017-March/003784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fafbdc2"
  );
  script_set_attribute(attribute:"solution", value:
"Update the affected gnutls packages. Note that the updated packages
may not be immediately available from the package repository and its
mirrors.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"gnutls-2.12.23-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-devel-2.12.23-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-guile-2.12.23-21.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-utils-2.12.23-21.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
