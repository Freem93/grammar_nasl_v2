#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-739.
#

include("compat.inc");

if (description)
{
  script_id(93251);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:42 $");

  script_cve_id("CVE-2016-6254");
  script_xref(name:"ALAS", value:"2016-739");

  script_name(english:"Amazon Linux AMI : collectd (ALAS-2016-739)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow in the parse_packet function in network.c
in collectd allows remote attackers to cause a denial of service
(daemon crash) or possibly execute arbitrary code via a crafted
network packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-739.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update collectd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-amqp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-curl_xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-generic-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-gmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-ipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-ipvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-lvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-memcachec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-netlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-notify_email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-rrdcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:collectd-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Collectd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"collectd-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-amqp-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-apache-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-bind-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-curl-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-curl_xml-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-dbi-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-debuginfo-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-dns-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-email-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-generic-jmx-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-gmond-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-ipmi-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-iptables-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-ipvs-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-java-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-lvm-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-memcachec-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-mysql-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-netlink-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-nginx-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-notify_email-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-postgresql-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-rrdcached-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-rrdtool-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-snmp-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-varnish-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"collectd-web-5.4.1-1.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Collectd-5.4.1-1.11.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "collectd / collectd-amqp / collectd-apache / collectd-bind / etc");
}
