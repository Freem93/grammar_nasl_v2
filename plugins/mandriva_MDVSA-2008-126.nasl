#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:126. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37584);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id(
    "CVE-2007-1649",
    "CVE-2007-4660",
    "CVE-2007-5898",
    "CVE-2007-5899",
    "CVE-2008-2051",
    "CVE-2008-2107",
    "CVE-2008-2108",
    "CVE-2008-2829"
  );
  script_bugtraq_id(
    23105,
    25498,
    26403,
    29829
  );
  script_osvdb_id(
    33943,
    38683,
    38918,
    44908,
    44909,
    44910,
    45874,
    46641
  );
  script_xref(name:"MDVSA", value:"2008:126");

  script_name(english:"Mandriva Linux Security Advisory : php (MDVSA-2008:126)");
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
"A number of vulnerabilities have been found and corrected in PHP :

PHP 5.2.1 would allow context-dependent attackers to read portions of
heap memory by executing certain scripts with a serialized data input
string beginning with 'S:', which did not properly track the number of
input bytes being processed (CVE-2007-1649).

A vulnerability in the chunk_split() function in PHP prior to 5.2.4
has unknown impact and attack vectors, related to an incorrect size
calculation (CVE-2007-4660).

The htmlentities() and htmlspecialchars() functions in PHP prior to
5.2.5 accepted partial multibyte sequences, which has unknown impact
and attack vectors (CVE-2007-5898).

The output_add_rewrite_var() function in PHP prior to 5.2.5 rewrites
local forms in which the ACTION attribute references a non-local URL,
which could allow a remote attacker to obtain potentially sensitive
information by reading the requests for this URL (CVE-2007-5899).

The escapeshellcmd() API function in PHP prior to 5.2.6 has unknown
impact and context-dependent attack vectors related to incomplete
multibyte characters (CVE-2008-2051).

Weaknesses in the GENERATE_SEED macro in PHP prior to 4.4.8 and 5.2.5
were discovered that could produce a zero seed in rare circumstances
on 32bit systems and generations a portion of zero bits during
conversion due to insufficient precision on 64bit systems
(CVE-2008-2107, CVE-2008-2108).

The IMAP module in PHP uses obsolete API calls that allow
context-dependent attackers to cause a denial of service (crash) via a
long IMAP request (CVE-2008-2829).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64php5_common5-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libphp5_common5-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-cgi-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-cli-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-devel-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-fcgi-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-imap-5.2.1-1.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-openssl-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"php-zlib-5.2.1-4.4mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
