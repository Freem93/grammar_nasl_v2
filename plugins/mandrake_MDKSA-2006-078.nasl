#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:078. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21284);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2006-0292", "CVE-2006-0293", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_xref(name:"MDKSA", value:"2006:078");

  script_name(english:"Mandrake Linux Security Advisory : mozilla-thunderbird (MDKSA-2006:078)");
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
"A number of vulnerabilities have been discovered in the Mozilla
Thunderbird email client that could allow a remote attacker to craft
malicious web emails that could take advantage of these issues to
execute arbitrary code with elevated privileges, spoof content, and
steal local files, or other information. As well, some of these
vulnerabilities can be exploited to execute arbitrary code with the
privileges of the user running the program.

As well, two crasher bugs have been fixed as well.

The updated packages have been patched to fix these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=275896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=330900"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mozilla-thunderbird, mozilla-thunderbird-enigmail
and / or mozilla-thunderbird-enigmime packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-1.0.6-7.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmail-1.0.6-7.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmime-1.0.6-7.6.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
