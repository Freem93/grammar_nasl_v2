#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:476 and 
# CentOS Errata and Security Advisory 2005:476 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21830);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-0975", "CVE-2005-0109");
  script_osvdb_id(11125, 16440);
  script_xref(name:"RHSA", value:"2005:476");

  script_name(english:"CentOS 3 / 4 : openssl (CESA-2005:476)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated OpenSSL packages that fix security issues are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a
full-strength general purpose cryptography library.

Colin Percival reported a cache timing attack that could allow a
malicious local user to gain portions of cryptographic keys. The
Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
the name CVE-2005-0109 to the issue. The OpenSSL library has been
patched to add a new fixed-window mod_exp implementation as default
for RSA, DSA, and DH private-key operations. This patch is designed to
mitigate cache timing and potentially related attacks.

A flaw was found in the way the der_chop script creates temporary
files. It is possible that a malicious local user could cause der_chop
to overwrite files (CVE-2004-0975). The der_chop script was deprecated
and has been removed from these updated packages. Red Hat Enterprise
Linux 4 did not ship der_chop and is therefore not vulnerable to this
issue.

Users are advised to update to these erratum packages which contain
patches to correct these issues.

Please note: After installing this update, users are advised to either
restart all services that use OpenSSL or restart their system."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79027d6f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011774.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?482dd6db"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a88924"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3eb29652"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?04a1d8c0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccc292b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl096b");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");
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
if (rpm_check(release:"CentOS-3", reference:"openssl-0.9.7a-33.15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-devel-0.9.7a-33.15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl-perl-0.9.7a-33.15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"openssl096b-0.9.6b-16.22.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"openssl-0.9.7a-43.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl-devel-0.9.7a-43.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl-perl-0.9.7a-43.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"openssl096b-0.9.6b-22.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
