#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0061 and 
# CentOS Errata and Security Advisory 2010:0061 respectively.
#

include("compat.inc");

if (description)
{
  script_id(44098);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2010-0001");
  script_osvdb_id(61869);
  script_xref(name:"RHSA", value:"2010:0061");

  script_name(english:"CentOS 3 / 4 / 5 : gzip (CESA-2010:0061)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gzip package that fixes one security issue is now available
for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gzip package provides the GNU gzip data compression program.

An integer underflow flaw, leading to an array index error, was found
in the way gzip expanded archive files compressed with the
Lempel-Ziv-Welch (LZW) compression algorithm. If a victim expanded a
specially crafted archive, it could cause gzip to crash or,
potentially, execute arbitrary code with the privileges of the user
running gzip. This flaw only affects 64-bit systems. (CVE-2010-0001)

Red Hat would like to thank Aki Helin of the Oulu University Secure
Programming Group for responsibly reporting this flaw.

Users of gzip should upgrade to this updated package, which contains a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?240a83cc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfaefc72"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f79f7c15"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71ac6a05"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d72d04ba"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbe6d55d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"gzip-1.3.3-15.rhel3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"gzip-1.3.3-15.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gzip-1.3.3-18.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gzip-1.3.3-18.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"gzip-1.3.5-11.el5.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
