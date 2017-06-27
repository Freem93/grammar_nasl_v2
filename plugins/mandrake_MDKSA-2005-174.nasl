#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:174. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20428);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2353", "CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
  script_xref(name:"MDKSA", value:"2005:174");

  script_name(english:"Mandrake Linux Security Advisory : mozilla-thunderbird (MDKSA-2005:174)");
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
"Updated Mozilla Thunderbird packages fix various vulnerabilities :

The run-mozilla.sh script, with debugging enabled, would allow local
users to create or overwrite arbitrary files via a symlink attack on
temporary files (CVE-2005-2353).

A bug in the way Thunderbird processes XBM images could be used to
execute arbitrary code via a specially crafted XBM image file
(CVE-2005-2701).

A bug in the way Thunderbird handles certain Unicode sequences could
be used to execute arbitrary code via viewing a specially crafted
Unicode sequence (CVE-2005-2702).

A bug in the way Thunderbird makes XMLHttp requests could be abused by
a malicious web page to exploit other proxy or server flaws from the
victim's machine; however, the default behaviour of the browser is to
disallow this (CVE-2005-2703).

A bug in the way Thunderbird implemented its XBL interface could be
abused by a malicious web page to create an XBL binding in such a way
as to allow arbitrary JavaScript execution with chrome permissions
(CVE-2005-2704).

An integer overflow in Thunderbird's JavaScript engine could be
manipulated in certain conditions to allow a malicious web page to
execute arbitrary code (CVE-2005-2705).

A bug in the way Thunderbird displays about: pages could be used to
execute JavaScript with chrome privileges (CVE-2005-2706).

A bug in the way Thunderbird opens new windows could be used by a
malicious web page to construct a new window without any user
interface elements (such as address bar and status bar) that could be
used to potentially mislead the user (CVE-2005-2707).

A bug in the way Thunderbird proceesed URLs on the command line could
be used to execute arbitary commands as the user running Thunderbird;
this could be abused by clicking on a supplied link, such as from an
instant messaging client (CVE-2005-2968).

Tom Ferris reported that Thunderbird would crash when processing a
domain name consisting solely of soft-hyphen characters due to a heap
overflow when IDN processing results in an empty string after removing
non-wrapping chracters, such as soft-hyphens. This could be exploited
to run or or install malware on the user's computer (CVE-2005-2871).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-57.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/mfsa2005-59.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.2", reference:"mozilla-thunderbird-1.0.2-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mozilla-thunderbird-devel-1.0.2-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mozilla-thunderbird-enigmail-1.0.2-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"mozilla-thunderbird-enigmime-1.0.2-5.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-1.0.6-7.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmail-1.0.6-7.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmime-1.0.6-7.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
