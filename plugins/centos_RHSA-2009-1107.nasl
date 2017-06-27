#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1107 and 
# CentOS Errata and Security Advisory 2009:1107 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43758);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
  script_bugtraq_id(35221, 35251, 35253);
  script_osvdb_id(55057, 55058, 55059);
  script_xref(name:"RHSA", value:"2009:1107");

  script_name(english:"CentOS 5 : apr-util (CESA-2009:1107)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apr-util packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

apr-util is a utility library used with the Apache Portable Runtime
(APR). It aims to provide a free library of C data structures and
routines. This library contains additional utility interfaces for APR;
including support for XML, LDAP, database interfaces, URI parsing, and
more.

An off-by-one overflow flaw was found in the way apr-util processed a
variable list of arguments. An attacker could provide a specially
crafted string as input for the formatted output conversion routine,
which could, on big-endian platforms, potentially lead to the
disclosure of sensitive information or a denial of service
(application crash). (CVE-2009-1956)

Note: The CVE-2009-1956 flaw only affects big-endian platforms, such
as the IBM S/390 and PowerPC. It does not affect users using the
apr-util package on little-endian platforms, due to their different
organization of byte ordering used to represent particular data.

A denial of service flaw was found in the apr-util Extensible Markup
Language (XML) parser. A remote attacker could create a specially
crafted XML document that would cause excessive memory consumption
when processed by the XML decoding engine. (CVE-2009-1955)

A heap-based underwrite flaw was found in the way apr-util created
compiled forms of particular search patterns. An attacker could
formulate a specially crafted search keyword, that would overwrite
arbitrary heap memory locations when processed by the pattern
preparation engine. (CVE-2009-0023)

All apr-util users should upgrade to these updated packages, which
contain backported patches to correct these issues. Applications using
the Apache Portable Runtime library, such as httpd, must be restarted
for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015983.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2330ee9f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-June/015984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?489671ef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apr-util packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"apr-util-1.2.7-7.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-util-devel-1.2.7-7.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-util-docs-1.2.7-7.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
