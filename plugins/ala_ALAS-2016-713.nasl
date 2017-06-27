#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-713.
#

include("compat.inc");

if (description)
{
  script_id(91627);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4556");
  script_xref(name:"ALAS", value:"2016-713");
  script_xref(name:"RHSA", value:"2016:1138");

  script_name(english:"Amazon Linux AMI : squid (ALAS-2016-713)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to
execute arbitrary code. (CVE-2016-4051)

Buffer overflow and input validation flaws were found in the way Squid
processed ESI responses. If Squid was used as a reverse proxy, or for
TLS/HTTPS interception, a remote attacker able to control ESI
components on an HTTP server could use these flaws to crash Squid,
disclose parts of the stack memory, or possibly execute arbitrary code
as the user running Squid. (CVE-2016-4052 , CVE-2016-4053 ,
CVE-2016-4054)

An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with
specially crafted header Host header that bypasses same-origin
security protections, causing Squid operating as interception or
reverse-proxy to contact the wrong origin server. It could also be
used for cache poisoning for client not following RFC 7230.
(CVE-2016-4554)

An incorrect reference counting flaw was found in the way Squid
processes ESI responses. If Squid is configured as reverse-proxy, for
TLS/HTTPS interception, an attacker controlling a server accessed by
Squid, could crash the squid worker, causing a Denial of Service
attack. (CVE-2016-4556)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-713.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update squid' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/16");
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
if (rpm_check(release:"ALA", reference:"squid-3.1.23-16.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"squid-debuginfo-3.1.23-16.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo");
}
