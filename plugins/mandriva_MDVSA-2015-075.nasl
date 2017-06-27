#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:075. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82328);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-1912", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185", "CVE-2014-9365");
  script_xref(name:"MDVSA", value:"2015:075");

  script_name(english:"Mandriva Linux Security Advisory : python (MDVSA-2015:075)");
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
"Updated python packages fix security vulnerabilities :

A vulnerability was reported in Python's socket module, due to a
boundary error within the sock_recvfrom_into() function, which could
be exploited to cause a buffer overflow. This could be used to crash a
Python application that uses the socket.recvfrom_info() function or,
possibly, execute arbitrary code with the permissions of the user
running vulnerable Python code (CVE-2014-1912).

This updates the python package to version 2.7.6, which fixes several
other bugs, including denial of service flaws due to unbound
readline() calls in the ftplib and nntplib modules (CVE-2013-1752).

Denial of service flaws due to unbound readline() calls in the
imaplib, poplib, and smtplib modules (CVE-2013-1752).

A gzip bomb and unbound read denial of service flaw in python XMLRPC
library (CVE-2013-1753).

Python are susceptible to arbitrary process memory reading by a user
or adversary due to a bug in the _json module caused by insufficient
bounds checking. The bug is caused by allowing the user to supply a
negative value that is used an an array index, causing the scanstring
function to access process memory outside of the string it is intended
to access (CVE-2014-4616).

The CGIHTTPServer Python module does not properly handle URL-encoded
path separators in URLs. This may enable attackers to disclose a CGI
script's source code or execute arbitrary scripts in the server's
document root (CVE-2014-4650).

Python before 2.7.8 is vulnerable to an integer overflow in the buffer
type (CVE-2014-7185).

When Python's standard library HTTP clients (httplib, urllib, urllib2,
xmlrpclib) are used to access resources with HTTPS, by default the
certificate is not checked against any trust store, nor is the
hostname in the certificate checked against the requested host. It was
possible to configure a trust root to be checked against, however
there were no faculties for hostname checking (CVE-2014-9365).

The python-pip and tix packages was added due to missing build
dependencies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0285.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0399.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python3-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tix-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tkinter-apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64python-devel-2.7.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64python2.7-2.7.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-2.7.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python-docs-2.7.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python-pip-1.4.1-4.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"python3-pip-1.4.1-4.2.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tix-8.4.3-9.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tix-devel-8.4.3-9.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tkinter-2.7.9-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"tkinter-apps-2.7.9-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
