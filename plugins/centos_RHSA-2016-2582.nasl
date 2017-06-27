#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2582 and 
# CentOS Errata and Security Advisory 2016:2582 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95329);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/28 15:05:43 $");

  script_cve_id("CVE-2015-8803", "CVE-2015-8804", "CVE-2015-8805", "CVE-2016-6489");
  script_osvdb_id(134093, 134094, 134095, 142565);
  script_xref(name:"RHSA", value:"2016:2582");

  script_name(english:"CentOS 7 : nettle (CESA-2016:2582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for nettle is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Nettle is a cryptographic library that is designed to fit easily in
almost any context: In cryptographic toolkits for object-oriented
languages, such as C++, Python, or Pike, in applications like lsh or
GnuPG, or even in kernel space.

Security Fix(es) :

* Multiple flaws were found in the way nettle implemented elliptic
curve scalar multiplication. These flaws could potentially introduce
cryptographic weaknesses into nettle's functionality. (CVE-2015-8803,
CVE-2015-8804, CVE-2015-8805)

* It was found that nettle's RSA and DSA decryption code was
vulnerable to cache-related side channel attacks. An attacker could
use this flaw to recover the private key from a co-located
virtual-machine instance. (CVE-2016-6489)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61870466"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nettle packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nettle-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nettle-2.7.1-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"nettle-devel-2.7.1-8.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
