#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:057. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(73004);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/10/03 10:46:58 $");

  script_cve_id("CVE-2013-6451", "CVE-2013-6452", "CVE-2013-6453", "CVE-2013-6472", "CVE-2014-1610", "CVE-2014-2242", "CVE-2014-2243", "CVE-2014-2244");
  script_bugtraq_id(65003, 65223, 65883, 65906, 65910);
  script_xref(name:"MDVSA", value:"2014:057");

  script_name(english:"Mandriva Linux Security Advisory : mediawiki (MDVSA-2014:057)");
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
"Updated mediawiki packages fix multiple vulnerabilities :

MediaWiki user Michael M reported that the fix for CVE-2013-4568
allowed insertion of escaped CSS values which could pass the CSS
validation checks, resulting in XSS (CVE-2013-6451).

Chris from RationalWiki reported that SVG files could be uploaded that
include external stylesheets, which could lead to XSS when an XSL was
used to include JavaScript (CVE-2013-6452).

During internal review, it was discovered that MediaWiki's SVG
sanitization could be bypassed when the XML was considered invalid
(CVE-2013-6453).

During internal review, it was discovered that MediaWiki displayed
some information about deleted pages in the log API, enhanced
RecentChanges, and user watchlists (CVE-2013-6472).

Netanel Rubin from Check Point discovered a remote code execution
vulnerability in MediaWiki's thumbnail generation for DjVu files.
Internal review also discovered similar logic in the PdfHandler
extension, which could be exploited in a similar way (CVE-2014-1610).

MediaWiki before 1.22.3 does not block unsafe namespaces, such as a
W3C XHTML namespace, in uploaded SVG files. Some client software may
use these namespaces in a way that results in XSS. This was fixed by
disallowing uploading SVG files using non-whitelisted namespaces
(CVE-2014-2242).

MediaWiki before 1.22.3 performs token comparison that may be
vulnerable to timing attacks. This was fixed by making token
comparison use constant time (CVE-2014-2243).

MediaWiki before 1.22.3 could allow an attacker to perform XSS
attacks, due to flaw with link handling in api.php. This was fixed
such that it won't find links in the middle of api.php links
(CVE-2014-2244).

MediaWiki has been updated to version 1.22.3, which fixes these
issues, as well as several others.

Also, the mediawiki-ldapauthentication and mediawiki-math extensions
have been updated to newer versions that are compatible with MediaWiki
1.22.

Additionally, the mediawiki-graphviz extension has been obsoleted, due
to the fact that it is unmaintained upstream and is vulnerable to
cross-site scripting attacks.

Note: if you were using the instances feature in these packages to
support multiple wiki instances, this feature has now been removed.
You will need to maintain separate wiki instances manually."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0124.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"MediaWiki thumb.php page Parameter Remote Shell Command Injection");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MediaWiki Thumb.php Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-ldapauthentication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mediawiki-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-1.22.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-ldapauthentication-2.0f-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-mysql-1.22.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-pgsql-1.22.3-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"mediawiki-sqlite-1.22.3-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
