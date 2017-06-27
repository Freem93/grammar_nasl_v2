#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:170. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19923);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871");
  script_xref(name:"MDKSA", value:"2005:170");

  script_name(english:"Mandrake Linux Security Advisory : mozilla (MDKSA-2005:170)");
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
"A number of vulnerabilities have been discovered in Mozilla that have
been corrected in version 1.7.12 :

A bug in the way Mozilla processes XBM images could be used to execute
arbitrary code via a specially crafted XBM image file (CVE-2005-2701).

A bug in the way Mozilla handles certain Unicode sequences could be
used to execute arbitrary code via viewing a specially crafted Unicode
sequence (CVE-2005-2702).

A bug in the way Mozilla makes XMLHttp requests could be abused by a
malicious web page to exploit other proxy or server flaws from the
victim's machine; however, the default behaviour of the browser is to
disallow this (CVE-2005-2703).

A bug in the way Mozilla implemented its XBL interface could be abused
by a malicious web page to create an XBL binding in such a way as to
allow arbitrary JavaScript execution with chrome permissions
(CVE-2005-2704).

An integer overflow in Mozilla's JavaScript engine could be
manipulated in certain conditions to allow a malicious web page to
execute arbitrary code (CVE-2005-2705).

A bug in the way Mozilla displays about: pages could be used to
execute JavaScript with chrome privileges (CVE-2005-2706).

A bug in the way Mozilla opens new windows could be used by a
malicious web page to construct a new window without any user
interface elements (such as address bar and status bar) that could be
used to potentially mislead the user (CVE-2005-2707).

Tom Ferris reported that Firefox would crash when processing a domain
name consisting solely of soft-hyphen characters due to a heap
overflow when IDN processing results in an empty string after removing
non- wrapping chracters, such as soft-hyphens. This could be exploited
to run or or install malware on the user's computer (CVE-2005-2871).

The updated packages have been patched to address these issues and all
users are urged to upgrade immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-57.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-58.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nspr4-devel-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64nss3-devel-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnspr4-devel-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libnss3-devel-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-devel-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-dom-inspector-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmail-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-enigmime-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-irc-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-js-debugger-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-mail-1.7.8-0.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"mozilla-spellchecker-1.7.8-0.3.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
