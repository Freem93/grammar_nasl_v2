#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0795 and 
# CentOS Errata and Security Advisory 2007:0795 respectively.
#

include("compat.inc");

if (description)
{
  script_id(26004);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/06/28 23:45:05 $");

  script_cve_id("CVE-2006-1721");
  script_osvdb_id(24510);
  script_xref(name:"RHSA", value:"2007:0795");

  script_name(english:"CentOS 4 : cyrus-sasl (CESA-2007:0795)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cyrus-sasl package that addresses a security issue and
fixes various other bugs is now available for Red Hat Enterprise Linux
4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The cyrus-sasl package contains the Cyrus implementation of SASL. SASL
is the Simple Authentication and Security Layer, a method for adding
authentication support to connection-based protocols.

A bug was found in cyrus-sasl's DIGEST-MD5 authentication mechanism.
As part of the DIGEST-MD5 authentication exchange, the client is
expected to send a specific set of information to the server. If one
of these items (the 'realm') was not sent or was malformed, it was
possible for a remote unauthenticated attacker to cause a denial of
service (segmentation fault) on the server. (CVE-2006-1721)

This errata also fixes the following bugs :

* the Kerberos 5 library included in Red Hat Enterprise Linux 4 was
not thread safe. This update adds functionality which allows it to be
used safely in a threaded application.

* several memory leak bugs were fixed in cyrus-sasl's DIGEST-MD5
authentication plug-in.

* /dev/urandom is now used by default on systems which don't support
hwrandom. Previously, dev/random was the default.

* cyrus-sasl needs zlib-devel to build properly. This dependency
information is now included in the package.

Users are advised to upgrade to this updated cyrus-sasl package, which
resolves these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014168.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59068e19"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014182.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09b7f628"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014183.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e10f9ea9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cyrus-sasl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-md5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cyrus-sasl-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-devel-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-gssapi-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-md5-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-ntlm-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-plain-2.1.19-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"cyrus-sasl-sql-2.1.19-14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
