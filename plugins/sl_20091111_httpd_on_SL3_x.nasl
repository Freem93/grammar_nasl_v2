#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60695);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-1891", "CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");

  script_name(english:"Scientific Linux Security Update : httpd on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-1891 httpd: possible temporary DoS (CPU consumption) in
mod_deflate

CVE-2009-3094 httpd: NULL pointer defer in mod_proxy_ftp caused by
crafted EPSV and PASV reply

CVE-2009-3095 httpd: mod_proxy_ftp FTP command injection via
Authorization HTTP header

CVE-2009-3555 TLS: MITM attacks via session renegotiation

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handle session renegotiation.
A man-in-the-middle attacker could use this flaw to prefix arbitrary
plain text to a client's session (for example, an HTTPS connection to
a website). This could force the server to process an attacker's
request as if authenticated using the victim's credentials. This
update partially mitigates this flaw for SSL sessions to HTTP servers
using mod_ssl by rejecting client-requested renegotiation.
(CVE-2009-3555)

Note: This update does not fully resolve the issue for HTTPS servers.
An attack is still possible in configurations that require a
server-initiated renegotiation. Refer to the following Knowledgebase
article for further information:
http://kbase.redhat.com/faq/docs/DOC-20491

A denial of service flaw was found in the Apache mod_deflate module.
This module continued to compress large files until compression was
complete, even if the network connection that requested the content
was closed before compression completed. This would cause mod_deflate
to consume large amounts of CPU if mod_deflate was enabled for a large
file. (CVE-2009-1891) - SL4 only

A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp
module. A malicious FTP server to which requests are being proxied
could use this flaw to crash an httpd child process via a malformed
reply to the EPSV or PASV commands, resulting in a limited denial of
service. (CVE-2009-3094)

A second flaw was found in the Apache mod_proxy_ftp module. In a
reverse proxy configuration, a remote attacker could use this flaw to
bypass intended access restrictions by creating a carefully-crafted
HTTP Authorization header, allowing the attacker to send arbitrary
commands to the FTP server. (CVE-2009-3095)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20491"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=1958
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ce883a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL3", reference:"httpd-2.0.46-77.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"httpd-devel-2.0.46-77.sl3")) flag++;
if (rpm_check(release:"SL3", reference:"mod_ssl-2.0.46-77.sl3")) flag++;

if (rpm_check(release:"SL4", reference:"httpd-2.0.52-41.sl4.6")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-41.sl4.6")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-41.sl4.6")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-41.sl4.6")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-41.sl4.6")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-31.sl5.2")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-31.sl5.2")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-31.sl5.2")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-31.sl5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
