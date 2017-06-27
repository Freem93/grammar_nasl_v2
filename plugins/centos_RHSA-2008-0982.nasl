#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0982 and 
# CentOS Errata and Security Advisory 2008:0982 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43716);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-4989");
  script_xref(name:"RHSA", value:"2008:0982");

  script_name(english:"CentOS 5 : gnutls (CESA-2008:0982)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix a security issue are now available
for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

Martin von Gagern discovered a flaw in the way GnuTLS verified
certificate chains provided by a server. A malicious server could use
this flaw to spoof its identity by tricking client applications using
the GnuTLS library to trust invalid certificates. (CVE-2008-4989)

Users of GnuTLS are advised to upgrade to these updated packages,
which contain a backported patch that corrects this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015391.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b19a18d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015392.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dea04fd0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"gnutls-1.4.1-3.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-devel-1.4.1-3.el5_2.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gnutls-utils-1.4.1-3.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
