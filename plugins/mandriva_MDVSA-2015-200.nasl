#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:200. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82686);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/15 13:45:11 $");

  script_cve_id("CVE-2015-2931", "CVE-2015-2932", "CVE-2015-2933", "CVE-2015-2934", "CVE-2015-2935", "CVE-2015-2936", "CVE-2015-2937", "CVE-2015-2938", "CVE-2015-2939", "CVE-2015-2940");
  script_bugtraq_id(73477);
  script_xref(name:"MDVSA", value:"2015:200");

  script_name(english:"Mandriva Linux Security Advisory : mediawiki (MDVSA-2015:200)");
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
"Updated mediawiki packages fix security vulnerabilities :

In MediaWiki before 1.23.9, one could circumvent the SVG MIME
blacklist for embedded resources. This allowed an attacker to embed
JavaScript in the SVG (CVE-2015-2931).

In MediaWiki before 1.23.9, the SVG filter to prevent injecting
JavaScript using animate elements was incorrect (CVE-2015-2932).

In MediaWiki before 1.23.9, a stored XSS vulnerability exists due to
the way attributes were expanded in MediaWiki's Html class, in
combination with LanguageConverter substitutions (CVE-2015-2933).

In MediaWiki before 1.23.9, MediaWiki's SVG filtering could be
bypassed with entity encoding under the Zend interpreter. This could
be used to inject JavaScript (CVE-2015-2934).

In MediaWiki before 1.23.9, one could bypass the style filtering for
SVG files to load external resources. This could violate the anonymity
of users viewing the SVG (CVE-2015-2935).

In MediaWiki before 1.23.9, MediaWiki versions using PBKDF2 for
password hashing (not the default for 1.23) are vulnerable to DoS
attacks using extremely long passwords (CVE-2015-2936).

In MediaWiki before 1.23.9, MediaWiki is vulnerable to Quadratic
Blowup DoS attacks, under both HHVM and Zend PHP (CVE-2015-2937).

In MediaWiki before 1.23.9, the MediaWiki feature allowing a user to
preview another user's custom JavaScript could be abused for privilege
escalation (CVE-2015-2938).

In MediaWiki before 1.23.9, function names were not sanitized in Lua
error backtraces, which could lead to XSS (CVE-2015-2939).

In MediaWiki before 1.23.9, the CheckUser extension did not prevent
CSRF attacks on the form allowing checkusers to look up sensitive
information about other users. Since the use of CheckUser is logged,
the CSRF could be abused to defame a trusted user or flood the logs
with noise (CVE-2015-2940).

The mediawiki package has been updated to version 1.23.9, fixing these
issues and other bugs."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0142.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-1.23.9-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-mysql-1.23.9-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-pgsql-1.23.9-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-sqlite-1.23.9-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
