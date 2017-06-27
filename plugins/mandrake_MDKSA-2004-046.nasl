#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:046. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14145);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/09/16 10:38:59 $");

  script_cve_id("CVE-2003-0020", "CVE-2003-0987", "CVE-2003-0993", "CVE-2004-0174", "CVE-2004-1082");
  script_xref(name:"MDKSA", value:"2004:046-1");

  script_name(english:"Mandrake Linux Security Advisory : apache-mod_perl (MDKSA-2004:046-1)");
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
"Four security vulnerabilities were fixed with the 1.3.31 release of
Apache. All of these issues have been backported and applied to the
provided packages. Thanks to Ralf Engelschall of OpenPKG for providing
the patches.

Apache 1.3 prior to 1.3.30 did not filter terminal escape sequences
from its error logs. This could make it easier for attackers to insert
those sequences into the terminal emulators of administrators viewing
the error logs that contain vulnerabilities related to escape sequence
handling (CVE-2003-0020).

mod_digest in Apache 1.3 prior to 1.3.31 did not properly verify the
nonce of a client response by using an AuthNonce secret. Apache now
verifies the nonce returned in the client response to check whether it
was issued by itself by means of a 'AuthDigestRealmSeed' secret
exposed as an MD5 checksum (CVE-2003-0987).

mod_access in Apache 1.3 prior to 1.3.30, when running on big-endian
64-bit platforms, did not properly parse Allow/Deny rules using IP
addresses without a netmask. This could allow a remote attacker to
bypass intended access restrictions (CVE-2003-0993).

Apache 1.3 prior to 1.3.30, when using multiple listening sockets on
certain platforms, allows a remote attacker to cause a DoS by blocking
new connections via a short-lived connection on a rarely-accessed
listening socket (CVE-2004-0174). While this particular vulnerability
does not affect Linux, we felt it prudent to include the fix.

Update :

Due to the changes in mod_digest.so, mod_perl needed to be rebuilt
against the patched Apache packages in order for httpd-perl to
properly load the module. The appropriate mod_perl packages have been
rebuilt and are now available."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:HTML-Embperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/20");
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
if (rpm_check(release:"MDK10.0", reference:"HTML-Embperl-1.3.29_1.3.6-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache-mod_perl-1.3.29_1.29-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mod_perl-common-1.3.29_1.29-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mod_perl-devel-1.3.29_1.29-3.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"HTML-Embperl-1.3.27_1.3.4-7.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"apache-mod_perl-1.3.27_1.27-7.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"mod_perl-common-1.3.27_1.27-7.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"mod_perl-devel-1.3.27_1.27-7.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"HTML-Embperl-1.3.28_1.3.4-1.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"apache-mod_perl-1.3.28_1.28-1.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mod_perl-common-1.3.28_1.28-1.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mod_perl-devel-1.3.28_1.28-1.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
