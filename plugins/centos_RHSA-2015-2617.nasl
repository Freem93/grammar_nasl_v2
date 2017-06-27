#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2617 and 
# CentOS Errata and Security Advisory 2015:2617 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87357);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_osvdb_id(131038, 131039, 131040);
  script_xref(name:"RHSA", value:"2015:2617");

  script_name(english:"CentOS 6 / 7 : openssl (CESA-2015:2617)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A NULL pointer dereference flaw was found in the way OpenSSL verified
signatures using the RSA PSS algorithm. A remote attacked could
possibly use this flaw to crash a TLS/SSL client using OpenSSL, or a
TLS/SSL server using OpenSSL if it enabled client authentication.
(CVE-2015-3194)

A memory leak vulnerability was found in the way OpenSSL parsed PKCS#7
and CMS data. A remote attacker could use this flaw to cause an
application that parses PKCS#7 or CMS data from untrusted sources to
use an excessive amount of memory and possibly crash. (CVE-2015-3195)

A race condition flaw, leading to a double free, was found in the way
OpenSSL handled pre-shared key (PSK) identify hints. A remote attacker
could use this flaw to crash a multi-threaded SSL/TLS client using
OpenSSL. (CVE-2015-3196)

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f022da6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021523.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef2e5d3e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-December/021524.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6882d5ed"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.1e-42.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.1e-42.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.1e-42.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.1e-42.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-51.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-51.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openssl-static-1.0.1e-51.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
