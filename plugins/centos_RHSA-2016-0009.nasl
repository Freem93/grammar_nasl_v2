#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0009 and 
# CentOS Errata and Security Advisory 2016:0009 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87782);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-3223", "CVE-2015-5330");
  script_osvdb_id(131935, 131940);
  script_xref(name:"RHSA", value:"2016:0009");

  script_name(english:"CentOS 6 / 7 : libldb (CESA-2016:0009)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libldb packages that fix two security issues are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libldb packages provide an extensible library that implements an
LDAP-like API to access remote LDAP servers, or use local TDB
databases.

A denial of service flaw was found in the ldb_wildcard_compare()
function of libldb. A remote attacker could send a specially crafted
packet that, when processed by an application using libldb (for
example the AD LDAP server in Samba), would cause that application to
consume an excessive amount of memory and crash. (CVE-2015-3223)

A memory-read flaw was found in the way the libldb library processed
LDB DN records with a null byte. An authenticated, remote attacker
could use this flaw to read heap-memory pages from the server.
(CVE-2015-5330)

Red Hat would like to thank the Samba project for reporting these
issues. Upstream acknowledges Thilo Uttendorfer as the original
reporter of CVE-2015-3223, and Douglas Bagnall as the original
reporter of CVE-2015-5330.

All libldb users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021598.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cc1a42e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a6f29b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libldb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pyldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pyldb-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");
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
if (rpm_check(release:"CentOS-6", reference:"ldb-tools-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libldb-devel-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pyldb-1.1.13-3.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pyldb-devel-1.1.13-3.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ldb-tools-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libldb-devel-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pyldb-1.1.20-1.el7_2.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pyldb-devel-1.1.20-1.el7_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
