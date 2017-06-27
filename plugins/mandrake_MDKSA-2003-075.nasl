#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:075. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14058);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0192", "CVE-2003-0253", "CVE-2003-0254");
  script_xref(name:"CERT", value:"379828");
  script_xref(name:"MDKSA", value:"2003:075-1");

  script_name(english:"Mandrake Linux Security Advisory : apache2 (MDKSA-2003:075-1)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Apache 2.x versions prior
to 2.0.47. From the Apache 2.0.47 release notes :

Certain sequences of per-directory renegotiations and the
SSLCipherSuite directive being used to upgrade from a weak ciphersuite
to a strong one could result in the weak ciphersuite being used in
place of the new one (CVE-2003-0192).

Certain errors returned by accept() on rarely accessed ports could
cause temporary Denial of Service due to a bug in the prefork MPM
(CVE-2003-0253).

Denial of Service was caused when target host is IPv6 but FTP proxy
server can't create IPv6 socket (CVE-2003-0254).

The server would crash when going into an infinite loop due to too
many subsequent internal redirects and nested subrequests (VU#379828).

The Apache Software Foundation thanks Saheed Akhtar and Yoshioka
Tsuneo for responsibly reporting these issues.

To upgrade these apache packages, first stop Apache by issuing, as
root :

service httpd stop

After the upgrade, restart Apache with :

service httpd start

Update :

The previously released packages had a manpage conflict between
apache2-common and apache-1.3 that prevented both packages from being
installed at the same time. This update provides a fixed
apache2-common package."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=105259038503175
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=105259038503175"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-common package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"apache2-common-2.0.47-1.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
