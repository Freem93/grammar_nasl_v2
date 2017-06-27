#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-557.
#

include("compat.inc");

if (description)
{
  script_id(84593);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/08 13:34:44 $");

  script_cve_id("CVE-2015-0261", "CVE-2015-2154");
  script_xref(name:"ALAS", value:"2015-557");

  script_name(english:"Amazon Linux AMI : tcpdump (ALAS-2015-557)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Integer signedness error in the mobility_opt_print function in the
IPv6 mobility printer in tcpdump before 4.7.2 allows remote attackers
to cause a denial of service (out-of-bounds read and crash) or
possibly execute arbitrary code via a negative length value.
(CVE-2015-0261)

The osi_print_cksum function in print-isoclns.c in the ethernet
printer in tcpdump before 4.7.2 allows remote attackers to cause a
denial of service (out-of-bounds read and crash) via a crafted (1)
length, (2) offset, or (3) base pointer checksum value.
(CVE-2015-2154)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-557.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update tcpdump' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"tcpdump-4.0.0-3.20090921gitdf3cb4.2.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"tcpdump-debuginfo-4.0.0-3.20090921gitdf3cb4.2.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump / tcpdump-debuginfo");
}
