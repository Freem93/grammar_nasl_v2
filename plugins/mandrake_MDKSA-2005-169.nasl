# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2005:169.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20425);
  script_version ("$Revision: 1.10 $"); 
  script_cvs_date("$Date: 2012/09/07 00:48:07 $");

  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");

  script_name(english:"MDKSA-2005:169 : mozilla-firefox");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A number of vulnerabilities have been discovered in Mozilla Firefox
that have been corrected in version 1.0.7:

A bug in the way Firefox processes XBM images could be used to
execute arbitrary code via a specially crafted XBM image file
(CVE-2005-2701).

A bug in the way Firefox handles certain Unicode sequences could be
used to execute arbitrary code via viewing a specially crafted
Unicode sequence (CVE-2005-2702).

A bug in the way Firefox makes XMLHttp requests could be abused by a
malicious web page to exploit other proxy or server flaws from the
victim's machine; however, the default behaviour of the browser is to
disallow this (CVE-2005-2703).

A bug in the way Firefox implemented its XBL interface could be
abused by a malicious web page to create an XBL binding in such a way
as to allow arbitrary JavaScript execution with chrome permissions
(CVE-2005-2704).

An integer overflow in Firefox's JavaScript engine could be
manipulated in certain conditions to allow a malicious web page to
execute arbitrary code (CVE-2005-2705).

A bug in the way Firefox displays about: pages could be used to
execute JavaScript with chrome privileges (CVE-2005-2706).

A bug in the way Firefox opens new windows could be used by a
malicious web page to construct a new window without any user
interface elements (such as address bar and status bar) that could be
used to potentially mislead the user (CVE-2005-2707).

A bug in the way Firefox proceesed URLs on the command line could be
used to execute arbitary commands as the user running Firefox; this
could be abused by clicking on a supplied link, such as from an
instant messaging client (CVE-2005-2968).

Tom Ferris reported that Firefox would crash when processing a domain
name consisting solely of soft-hyphen characters due to a heap
overflow when IDN processing results in an empty string after
removing non- wrapping chracters, such as soft-hyphens. This could be
exploited to run or or install malware on the user's computer
(CVE-2005-2871).

The updated packages have been patched to address these issues and
all users are urged to upgrade immediately.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:169");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(94);
  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"libnspr4-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnspr4-devel-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnss3-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libnss3-devel-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-firefox-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"mozilla-firefox-devel-1.0.2-9.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"mozilla-firefox-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-2701", value:TRUE);
    set_kb_item(name:"CVE-2005-2702", value:TRUE);
    set_kb_item(name:"CVE-2005-2703", value:TRUE);
    set_kb_item(name:"CVE-2005-2704", value:TRUE);
    set_kb_item(name:"CVE-2005-2705", value:TRUE);
    set_kb_item(name:"CVE-2005-2706", value:TRUE);
    set_kb_item(name:"CVE-2005-2707", value:TRUE);
    set_kb_item(name:"CVE-2005-2871", value:TRUE);
    set_kb_item(name:"CVE-2005-2968", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
