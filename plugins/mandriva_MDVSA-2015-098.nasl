#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:098. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82351);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-0015", "CVE-2014-0138", "CVE-2014-0139", "CVE-2014-3613", "CVE-2014-3620", "CVE-2014-3707", "CVE-2014-8150");
  script_xref(name:"MDVSA", value:"2015:098");

  script_name(english:"Mandriva Linux Security Advisory : curl (MDVSA-2015:098)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated curl packages fix security vulnerabilities :

Paras Sethia discovered that libcurl would sometimes mix up multiple
HTTP and HTTPS connections with NTLM authentication to the same
server, sending requests for one user over the connection
authenticated as a different user (CVE-2014-0015).

libcurl can in some circumstances re-use the wrong connection when
asked to do transfers using other protocols than HTTP and FTP, causing
a transfer that was initiated by an application to wrongfully re-use
an existing connection to the same server that was authenticated using
different credentials (CVE-2014-0138).

libcurl incorrectly validates wildcard SSL certificates containing
literal IP addresses, so under certain conditions, it would allow and
use a wildcard match specified in the CN field, allowing a malicious
server to participate in a MITM attack or just fool users into
believing that it is a legitimate site (CVE-2014-0139).

In cURL before 7.38.0, libcurl can be fooled to both sending cookies
to wrong sites and into allowing arbitrary sites to set cookies for
others. For this problem to trigger, the client application must use
the numerical IP address in the URL to access the site
(CVE-2014-3613).

In cURL before 7.38.0, libcurl wrongly allows cookies to be set for
Top Level Domains (TLDs), thus making them apply broader than cookies
are allowed. This can allow arbitrary sites to set cookies that then
would get sent to a different and unrelated site or domain
(CVE-2014-3620).

Symeon Paraschoudis discovered that the curl_easy_duphandle() function
in cURL has a bug that can lead to libcurl eventually sending off
sensitive data that was not intended for sending, while performing a
HTTP POST operation. This bug requires CURLOPT_COPYPOSTFIELDS and
curl_easy_duphandle() to be used in that order, and then the duplicate
handle must be used to perform the HTTP POST. The curl command line
tool is not affected by this problem as it does not use this sequence
(CVE-2014-3707).

When libcurl sends a request to a server via a HTTP proxy, it copies
the entire URL into the request and sends if off. If the given URL
contains line feeds and carriage returns those will be sent along to
the proxy too, which allows the program to for example send a separate
HTTP request injected embedded in the URL (CVE-2014-8150)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0020.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"curl-7.34.0-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"curl-examples-7.34.0-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64curl-devel-7.34.0-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64curl4-7.34.0-3.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
