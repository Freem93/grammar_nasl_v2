#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:168. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82421);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-3406", "CVE-2014-0475", "CVE-2014-4043", "CVE-2014-5119", "CVE-2014-6040", "CVE-2014-7817", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_xref(name:"MDVSA", value:"2015:168");

  script_name(english:"Mandriva Linux Security Advisory : glibc (MDVSA-2015:168)");
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
"Updated glibc packages fix security vulnerabilities :

Stephane Chazelas discovered that directory traversal issue in locale
handling in glibc. glibc accepts relative paths with .. components in
the LC_* and LANG variables. Together with typical OpenSSH
configurations (with suitable AcceptEnv settings in sshd_config), this
could conceivably be used to bypass ForceCommand restrictions (or
restricted shells), assuming the attacker has sufficient level of
access to a file system location on the host to create crafted locale
definitions there (CVE-2014-0475).

David Reid, Glyph Lefkowitz, and Alex Gaynor discovered a bug where
posix_spawn_file_actions_addopen fails to copy the path argument
(glibc bz #17048) which can, in conjunction with many common memory
management techniques from an application, lead to a use after free,
or other vulnerabilities (CVE-2014-4043).

This update also fixes the following issues: x86: Disable x87 inline
functions for SSE2 math (glibc bz #16510) malloc: Fix race in free()
of fastbin chunk (glibc bz #15073)

Tavis Ormandy discovered a heap-based buffer overflow in the
transliteration module loading code. As a result, an attacker who can
supply a crafted destination character set argument to iconv-related
character conversation functions could achieve arbitrary code
execution.

This update removes support of loadable gconv transliteration modules.
Besides the security vulnerability, the module loading code had
functionality defects which prevented it from working for the intended
purpose (CVE-2014-5119).

Adhemerval Zanella Netto discovered out-of-bounds reads in additional
code page decoding functions (IBM933, IBM935, IBM937, IBM939, IBM1364)
that can be used to crash the systems, causing a denial of service
conditions (CVE-2014-6040).

The function wordexp() fails to properly handle the WRDE_NOCMD flag
when processing arithmetic inputs in the form of '$((... ))' where
'...' can be anything valid. The backticks in the arithmetic
epxression are evaluated by in a shell even if WRDE_NOCMD forbade
command substitution. This allows an attacker to attempt to pass
dangerous commands via constructs of the above form, and bypass the
WRDE_NOCMD flag. This update fixes the issue (CVE-2014-7817).

The vfprintf function in stdio-common/vfprintf.c in GNU C Library (aka
glibc) 2.5, 2.12, and probably other versions does not properly
restrict the use of the alloca function when allocating the SPECS
array, which allows context-dependent attackers to bypass the
FORTIFY_SOURCE format-string protection mechanism and cause a denial
of service (crash) or possibly execute arbitrary code via a crafted
format string using positional parameters and a large number of format
specifiers (CVE-2012-3406).

The nss_dns implementation of getnetbyname could run into an infinite
loop if the DNS response contained a PTR record of an unexpected
format (CVE-2014-9402).

Also glibc lock elision (new feature in glibc 2.18) has been disabled
as it can break glibc at runtime on newer Intel hardware (due to
hardware bug)

Under certain conditions wscanf can allocate too little memory for the
to-be-scanned arguments and overflow the allocated buffer
(CVE-2015-1472).

The incorrect use of '__libc_use_alloca (newsize)' caused a different
(and weaker) policy to be enforced which could allow a denial of
service attack (CVE-2015-1473)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0314.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0376.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0072.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-devel-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"glibc-doc-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-i18ndata-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-profile-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-static-devel-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"glibc-utils-2.18-10.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"nscd-2.18-10.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
