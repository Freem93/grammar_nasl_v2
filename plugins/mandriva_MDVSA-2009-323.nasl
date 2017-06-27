#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:323. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43042);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2008-1678", "CVE-2008-2939", "CVE-2009-1191", "CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891", "CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_bugtraq_id(30560, 31692, 34663, 35115, 35565, 35623, 36254, 36260, 36935);
  script_xref(name:"MDVSA", value:"2009:323");

  script_name(english:"Mandriva Linux Security Advisory : apache (MDVSA-2009:323)");
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
"Multiple vulnerabilities has been found and corrected in apache :

Memory leak in the zlib_stateful_init function in crypto/comp/c_zlib.c
in libssl in OpenSSL 0.9.8f through 0.9.8h allows remote attackers to
cause a denial of service (memory consumption) via multiple calls, as
demonstrated by initial SSL client handshakes to the Apache HTTP
Server mod_ssl that specify a compression algorithm (CVE-2008-1678).
Note that this security issue does not really apply as zlib
compression is not enabled in the openssl build provided by Mandriva,
but apache is patched to address this issue anyway (conserns 2008.1
only).

mod_proxy_ajp.c in the mod_proxy_ajp module in the Apache HTTP Server
2.2.11 allows remote attackers to obtain sensitive response data,
intended for a client that sent an earlier POST request with no
request body, via an HTTP request (CVE-2009-1191).

Cross-site scripting (XSS) vulnerability in proxy_ftp.c in the
mod_proxy_ftp module in Apache 2.0.63 and earlier, and mod_proxy_ftp.c
in the mod_proxy_ftp module in Apache 2.2.9 and earlier 2.2 versions,
allows remote attackers to inject arbitrary web script or HTML via
wildcards in a pathname in an FTP URI (CVE-2008-2939). Note that this
security issue was initially addressed with MDVSA-2008:195 but the
patch fixing the issue was added but not applied in 2009.0.

The Apache HTTP Server 2.2.11 and earlier 2.2 versions does not
properly handle Options=IncludesNOEXEC in the AllowOverride directive,
which allows local users to gain privileges by configuring (1) Options
Includes, (2) Options +Includes, or (3) Options +IncludesNOEXEC in a
.htaccess file, and then inserting an exec element in a .shtml file
(CVE-2009-1195).

The stream_reqbody_cl function in mod_proxy_http.c in the mod_proxy
module in the Apache HTTP Server before 2.3.3, when a reverse proxy is
configured, does not properly handle an amount of streamed data that
exceeds the Content-Length value, which allows remote attackers to
cause a denial of service (CPU consumption) via crafted requests
(CVE-2009-1890).

Fix a potential Denial-of-Service attack against mod_deflate or other
modules, by forcing the server to consume CPU time in compressing a
large file after a client disconnects (CVE-2009-1891).

The ap_proxy_ftp_handler function in modules/proxy/proxy_ftp.c in the
mod_proxy_ftp module in the Apache HTTP Server 2.0.63 and 2.2.13
allows remote FTP servers to cause a denial of service (NULL pointer
dereference and child process crash) via a malformed reply to an EPSV
command (CVE-2009-3094).

The mod_proxy_ftp module in the Apache HTTP Server allows remote
attackers to bypass intended access restrictions and send arbitrary
commands to an FTP server via vectors related to the embedding of
these commands in the Authorization HTTP header, as demonstrated by a
certain module in VulnDisco Pack Professional 8.11. NOTE: as of
20090903, this disclosure has no actionable information. However,
because the VulnDisco Pack author is a reliable researcher, the issue
is being assigned a CVE identifier for tracking purposes
(CVE-2009-3095).

Apache is affected by SSL injection or man-in-the-middle attacks due
to a design flaw in the SSL and/or TLS protocols. A short term
solution was released Sat Nov 07 2009 by the ASF team to mitigate
these problems. Apache will now reject in-session renegotiation
(CVE-2009-3555).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

This update provides a solution to these vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=apache-httpd-announce&m=125755783724966&w=2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 119, 189, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-htcacheclean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_authn_dbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_dbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_disk_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_file_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_mem_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_proxy_ajp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_userdir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"apache-base-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-devel-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-htcacheclean-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_authn_dbd-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_cache-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_dav-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_dbd-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_deflate-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_disk_cache-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_file_cache-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_ldap-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_mem_cache-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_proxy-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_proxy_ajp-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_ssl-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mod_userdir-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-modules-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mpm-event-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mpm-itk-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mpm-prefork-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-mpm-worker-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"apache-source-2.2.6-8.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
