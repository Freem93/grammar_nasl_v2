#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:082. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(14331);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/11/14 18:38:14 $");

  script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0718", "CVE-2004-0722", "CVE-2004-0757", "CVE-2004-0758", "CVE-2004-0759", "CVE-2004-0760", "CVE-2004-0761", "CVE-2004-0762", "CVE-2004-0763", "CVE-2004-0764", "CVE-2004-0765", "CVE-2004-0779", "CVE-2004-1449", "CVE-2005-1937");
  script_xref(name:"MDKSA", value:"2004:082");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2004:082)");
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
"A number of security vulnerabilities in mozilla are addressed by this
update for Mandrakelinux 10.0 users, including a fix for frame
spoofing, a fixed popup XPInstall/security dialog bug, a fix for
untrusted chrome calls, a fix for SSL certificate spoofing, a fix for
stealing secure HTTP Auth passwords via DNS spoofing, a fix for
insecure matching of cert names for non-FQDNs, a fix for focus
redefinition from another domain, a fix for a SOAP parameter overflow,
a fix for text drag on file entry, a fix for certificate DoS, and a
fix for lock icon and cert spoofing.

Additionally, mozilla for both Mandrakelinux 9.2 and 10.0 have been
rebuilt to use the system libjpeg and libpng which addresses
vulnerabilities discovered in libpng (ref: MDKSA-2004:079)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=149478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=162020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=206859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=226278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=229374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=234058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=236618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=239580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=240053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=244965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=246448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=249004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=253121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=86028"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nspr4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nss3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnspr4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnss3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-enigmime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-spellchecker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64nspr4-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64nspr4-devel-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64nss3-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64nss3-devel-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libnspr4-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libnspr4-devel-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libnss3-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libnss3-devel-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-devel-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-dom-inspector-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-enigmail-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-enigmime-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-irc-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-js-debugger-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-mail-1.6-12.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mozilla-spellchecker-1.6-12.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nspr4-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nspr4-devel-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nss3-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nss3-devel-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnspr4-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnspr4-devel-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnss3-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnss3-devel-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-devel-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-dom-inspector-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-enigmail-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-enigmime-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-irc-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-js-debugger-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-mail-1.4-13.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-spellchecker-1.4-13.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
