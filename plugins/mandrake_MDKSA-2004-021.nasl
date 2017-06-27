#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:021. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14120);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2003-0564", "CVE-2003-0594", "CVE-2003-0791");
  script_xref(name:"CERT", value:"428230");
  script_xref(name:"MDKSA", value:"2004:021");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2004:021)");
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
"A number of vulnerabilities were discovered in Mozilla 1.4 :

A malicious website could gain access to a user's authentication
credentials to a proxy server.

Script.prototype.freeze/thaw could allow an attacker to run arbitrary
code on your computer.

A vulnerability was also discovered in the NSS security suite which
ships with Mozilla. The S/MIME implementation would allow remote
attackers to cause a Denial of Service and possibly execute arbitrary
code via an S/MIME email message containing certain unexpected ASN.1
constructs, which was demonstrated using the NISCC test suite. NSS
version 3.9 corrects these problems and has been included in this
package (which shipped with NSS 3.8).

Finally, Corsaire discovered that a number of HTTP user agents
contained a flaw in how they handle cookies. This flaw could allow an
attacker to avoid the path restrictions specified by a cookie's
originator. According to their advisory :

'The cookie specifications detail a path argument that can be used to
restrict the areas of a host that will be exposed to a cookie. By
using standard traversal techniques this functionality can be
subverted, potentially exposing the cookie to scrutiny and use in
further attacks.'

As well, a bug with Mozilla and Finnish keyboards has been corrected.

The updated packages are patched to correct these vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=213012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=220122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.mozilla.org/show_bug.cgi?id=221526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.uniras.gov.uk/vuls/2003/006489/smime.htm"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/10");
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
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nspr4-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nspr4-devel-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nss3-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64nss3-devel-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnspr4-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnspr4-devel-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnss3-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libnss3-devel-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-devel-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-dom-inspector-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-enigmail-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-enigmime-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-irc-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-js-debugger-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-mail-1.4-13.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"mozilla-spellchecker-1.4-13.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
