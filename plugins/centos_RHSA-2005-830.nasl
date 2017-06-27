#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:830 and 
# CentOS Errata and Security Advisory 2005:830 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21870);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2004-0079");
  script_bugtraq_id(9899);
  script_osvdb_id(4317);
  script_xref(name:"RHSA", value:"2005:830");

  script_name(english:"CentOS 3 / 4 : openssl096b (CESA-2005:830)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL096b compatibility packages that fix a remote denial of
service vulnerability are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The OpenSSL toolkit implements Secure Sockets Layer (SSL v2/v3),
Transport Layer Security (TLS v1) protocols, and serves as a
full-strength general purpose cryptography library. OpenSSL 0.9.6b
libraries are provided for Red Hat Enterprise Linux 3 and 4 to allow
compatibility with legacy applications.

Testing performed by the OpenSSL group using the Codenomicon TLS Test
Tool uncovered a NULL pointer assignment in the
do_change_cipher_spec() function. A remote attacker could perform a
carefully crafted SSL/TLS handshake against a server that uses the
OpenSSL library in such a way as to cause OpenSSL to crash. Depending
on the server this could lead to a denial of service. (CVE-2004-0079)

This issue was reported as not affecting OpenSSL versions prior to
0.9.6c, and testing with the Codenomicon Test Tool showed that OpenSSL
0.9.6b as shipped as a compatibility library with Red Hat Enterprise
Linux 3 and 4 did not crash. However, an alternative reproducer has
been written which shows that this issue does affect versions of
OpenSSL prior to 0.9.6c.

Note that Red Hat does not ship any applications with Red Hat
Enterprise Linux 3 or 4 that use these compatibility libraries.

Users of the OpenSSL096b compatibility package are advised to upgrade
to these updated packages, which contain a patch provided by the
OpenSSL group that protect against this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed8e61e0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012357.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d19a366b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a99663c9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b154a0d3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012373.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82eda187"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012374.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9db703fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl096b package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/17");
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
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.42")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssl096b-0.9.6b-22.42")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
