#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:113. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(74446);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/11 15:40:01 $");

  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474", "CVE-2014-1418", "CVE-2014-3730");
  script_bugtraq_id(67038, 67040, 67041, 67408, 67410);
  script_xref(name:"MDVSA", value:"2014:113");

  script_name(english:"Mandriva Linux Security Advisory : python-django (MDVSA-2014:113)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in
python-django :

Django 1.4 before 1.4.13, 1.5 before 1.5.8, 1.6 before 1.6.5, and 1.7
before 1.7b4 does not properly include the (1) Vary: Cookie or (2)
Cache-Control header in responses, which allows remote attackers to
obtain sensitive information or poison the cache via a request from
certain browsers (CVE-2014-1418).

The django.util.http.is_safe_url function in Django 1.4 before 1.4.13,
1.5 before 1.5.8, 1.6 before 1.6.5, and 1.7 before 1.7b4 does not
properly validate URLs, which allows remote attackers to conduct open
redirect attacks via a malformed URL, as demonstrated by
http:\djangoproject.com. (CVE-2014-3730).

The django.core.urlresolvers.reverse function in Django before 1.4.11,
1.5.x before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2
allows remote attackers to import and execute arbitrary Python modules
by leveraging a view that constructs URLs using user input and a
dotted Python path. (CVE-2014-0472).

The caching framework in Django before 1.4.11, 1.5.x before 1.5.6,
1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 reuses a cached CSRF
token for all anonymous users, which allows remote attackers to bypass
CSRF protections by reading the CSRF cookie for anonymous users
(CVE-2014-0473).

The (1) FilePathField, (2) GenericIPAddressField, and (3)
IPAddressField model field classes in Django before 1.4.11, 1.5.x
before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 do not
properly perform type conversion, which allows remote attackers to
have unspecified impact and vectors, related to MySQL typecasting.
(CVE-2014-0474).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");
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
if (rpm_check(release:"MDK-MBS1", reference:"python-django-1.3.7-1.4.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
