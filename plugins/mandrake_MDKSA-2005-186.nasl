#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:186. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20057);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2665", "CVE-2005-3120");
  script_xref(name:"MDKSA", value:"2005:186-1");

  script_name(english:"Mandrake Linux Security Advisory : lynx (MDKSA-2005:186-1)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ulf Harnhammar discovered a remote buffer overflow in lynx versions
2.8.2 through 2.8.5.

When Lynx connects to an NNTP server to fetch information about the
available articles in a newsgroup, it will call a function called
HTrjis() with the information from certain article headers. The
function adds missing ESC characters to certain data, to support Asian
character sets. However, it does not check if it writes outside of the
char array buf, and that causes a remote stack-based buffer overflow,
with full control over EIP, EBX, EBP, ESI and EDI.

Two attack vectors to make a victim visit a URL to a dangerous news
server are: (a) *redirecting scripts*, where the victim visits some
web page and it redirects automatically to a malicious URL, and (b)
*links in web pages*, where the victim visits some web page and
selects a link on the page to a malicious URL. Attack vector (b) is
helped by the fact that Lynx does not automatically display where
links lead to, unlike many graphical web browsers.

The updated packages have been patched to address this issue.

Update :

The previous patchset had a bug in the patches themselves, which was
uncovered by Klaus Singvogel of Novell/SUSE in auditing crashes on
some architectures."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
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
if (rpm_check(release:"MDK10.1", reference:"lynx-2.8.5-1.2.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"lynx-2.8.5-1.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"lynx-2.8.5-4.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
