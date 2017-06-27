#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-157.
#

include("compat.inc");

if (description)
{
  script_id(69716);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/01/17 15:50:10 $");

  script_cve_id("CVE-2012-3955");
  script_xref(name:"ALAS", value:"2013-157");
  script_xref(name:"RHSA", value:"2013:0504");

  script_name(english:"Amazon Linux AMI : dhcp (ALAS-2013-157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way the dhcpd daemon handled the expiration
time of IPv6 leases. If dhcpd's configuration was changed to reduce
the default IPv6 lease time, lease renewal requests for previously
assigned leases could cause dhcpd to crash. (CVE-2012-3955)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-157.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dhcp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"dhclient-4.1.1-34.P1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dhcp-4.1.1-34.P1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dhcp-common-4.1.1-34.P1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dhcp-debuginfo-4.1.1-34.P1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dhcp-devel-4.1.1-34.P1.18.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-debuginfo / dhcp-devel");
}
