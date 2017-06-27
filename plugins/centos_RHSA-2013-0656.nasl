#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0656 and 
# CentOS Errata and Security Advisory 2013:0656 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65618);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/29 00:03:04 $");

  script_cve_id("CVE-2012-1016", "CVE-2013-1415");
  script_osvdb_id(90609, 90895);
  script_xref(name:"RHSA", value:"2013:0656");

  script_name(english:"CentOS 6 : krb5 (CESA-2013:0656)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other using symmetric encryption and a
trusted third-party, the Key Distribution Center (KDC).

When a client attempts to use PKINIT to obtain credentials from the
KDC, the client can specify, using an issuer and serial number, which
of the KDC's possibly-many certificates the client has in its
possession, as a hint to the KDC that it should use the corresponding
key to sign its response. If that specification was malformed, the KDC
could attempt to dereference a NULL pointer and crash. (CVE-2013-1415)

When a client attempts to use PKINIT to obtain credentials from the
KDC, the client will typically format its request to conform to the
specification published in RFC 4556. For interoperability reasons,
clients and servers also provide support for an older, draft version
of that specification. If a client formatted its request to conform to
this older version of the specification, with a non-default key
agreement option, it could cause the KDC to attempt to dereference a
NULL pointer and crash. (CVE-2012-1016)

All krb5 users should upgrade to these updated packages, which contain
backported patches to correct these issues. After installing the
updated packages, the krb5kdc daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a989ada"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-pkinit-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"krb5-devel-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-libs-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-pkinit-openssl-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-server-ldap-1.10.3-10.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"krb5-workstation-1.10.3-10.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
