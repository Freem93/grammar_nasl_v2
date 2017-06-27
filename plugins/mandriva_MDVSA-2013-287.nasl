#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:287. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(71101);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/12/27 15:24:34 $");

  script_cve_id("CVE-2013-0316", "CVE-2013-6385", "CVE-2013-6386", "CVE-2013-6387", "CVE-2013-6388", "CVE-2013-6389");
  script_bugtraq_id(58069);
  script_xref(name:"MDVSA", value:"2013:287-1");

  script_name(english:"Mandriva Linux Security Advisory : drupal (MDVSA-2013:287-1)");
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
"Multiple security issues was identified and fixed in drupal :

Drupal core's Image module allows for the on-demand generation of
image derivatives. This capability can be abused by requesting a large
number of new derivatives which can fill up the server disk space, and
which can cause a very high CPU load. Either of these effects may lead
to the site becoming unavailable or unresponsive (CVE-2013-0316).

Drupal's form API has built-in cross-site request forgery (CSRF)
validation, and also allows any module to perform its own validation
on the form. In certain common cases, form validation functions may
execute unsafe operations (CVE-2013-6385).

Drupal core directly used the mt_rand() pseudorandom number generator
for generating security related strings used in several core modules.
It was found that brute force tools could determine the seeds making
these strings predictable under certain circumstances (CVE-2013-6386).

Image field descriptions are not properly sanitized before they are
printed to HTML, thereby exposing a cross-site scripting vulnerability
(CVE-2013-6387).

A cross-site scripting vulnerability was found in the Color module. A
malicious attacker could trick an authenticated administrative user
into visiting a page containing specific JavaScript that could lead to
a reflected cross-site scripting attack via JavaScript execution in
CSS (CVE-2013-6388).

The Overlay module displays administrative pages as a layer over the
current page (using JavaScript), rather than replacing the page in the
browser window. The Overlay module did not sufficiently validate URLs
prior to displaying their contents, leading to an open redirect
vulnerability (CVE-2013-6389).

The updated packages has been upgraded to the 7.24 version which is
unaffected by these security flaws.

Update :

Additional apache ACL restrictions has been added to fully conform to
the SA-CORE-2013-003 advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drupal.org/SA-CORE-2013-002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drupal.org/SA-CORE-2013-003"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"drupal-7.24-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-mysql-7.24-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-postgresql-7.24-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-sqlite-7.24-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
