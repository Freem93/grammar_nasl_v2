#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:046. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13949);
  script_version ("$Revision: 1.24 $");
  script_cvs_date("$Date: 2014/06/27 10:42:17 $");

  script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0657");
  script_xref(name:"MDKSA", value:"2002:046-1");

  script_name(english:"Mandrake Linux Security Advisory : openssl (MDKSA-2002:046-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An audit of the OpenSSL code by A.L. Digital Ltd and The Bunker, under
the DARPA program CHATS, discovered a number of vulnerabilities in the
OpenSSL code that are all potentially remotely exploitable.

From the OpenSSL advisory :

1. The client master key in SSL2 could be oversized and overrun a
buffer. This vulnerability was also independently discovered by
consultants at Neohapsis (http://www.neohapsis.com/) who have also
demonstrated that the vulerability is exploitable. Exploit code is NOT
available at this time.

2. The session ID supplied to a client in SSL3 could be oversized and
overrun a buffer.

3. The master key supplied to an SSL3 server could be oversized and
overrun a stack-based buffer. This issues only affects OpenSSL 0.9.7
with Kerberos enabled.

4. Various buffers for ASCII representations of integers were too
small on 64 bit platforms.

At the same time, various potential buffer overflows have had
assertions added; these are not known to be exploitable.

Finally, a vulnerability was found by Adi Stav and James Yonan
independently in the ASN1 parser which can be confused by supplying it
with certain invalid encodings. There are no known exploits for this
vulnerability.

All of these vulnerabilities are fixed in OpenSSL 0.9.6f. Patches have
been applied to the versions of OpenSSL provided in this update to fix
all of these problems, except for the ASN1 vulnerability, which a fix
will be provided for once MandrakeSoft has had a chance to QA the new
packages. In the meantime, it is is strongly encouraged that all users
upgrade to these OpenSSL packages.

Update :

These new OpenSSL packages are available to additionally fix the ASN1
vulnerability described above. All Mandrake Linux users are encouraged
to upgrade to these new packages."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libopenssl0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssl-0.9.5a-4.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"openssl-devel-0.9.5a-4.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssl-0.9.5a-9.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"openssl-devel-0.9.5a-9.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssl-0.9.6-8.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"openssl-devel-0.9.6-8.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libopenssl0-0.9.6b-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libopenssl0-devel-0.9.6b-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"openssl-0.9.6b-1.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libopenssl0-0.9.6c-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libopenssl0-devel-0.9.6c-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"openssl-0.9.6c-2.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
