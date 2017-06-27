#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:239. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(70005);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/04/20 04:29:52 $");

  script_cve_id("CVE-2013-4338", "CVE-2013-4339", "CVE-2013-4340", "CVE-2013-5738", "CVE-2013-5739");
  script_bugtraq_id(62344, 62345, 62346, 62421, 62424);
  script_xref(name:"MDVSA", value:"2013:239");

  script_name(english:"Mandriva Linux Security Advisory : wordpress (MDVSA-2013:239)");
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
"Updated wordpress and php-phpmailer packages fix security
vulnerabilities :

wp-includes/functions.php in WordPress before 3.6.1 does not properly
determine whether data has been serialized, which allows remote
attackers to execute arbitrary code by triggering erroneous PHP
unserialize operations (CVE-2013-4338).

WordPress before 3.6.1 does not properly validate URLs before use in
an HTTP redirect, which allows remote attackers to bypass intended
redirection restrictions via a crafted string (CVE-2013-4339).

wp-admin/includes/post.php in WordPress before 3.6.1 allows remote
authenticated users to spoof the authorship of a post by leveraging
the Author role and providing a modified user_ID parameter
(CVE-2013-4340).

The get_allowed_mime_types function in wp-includes/functions.php in
WordPress before 3.6.1 does not require the unfiltered_html capability
for uploads of .htm and .html files, which might make it easier for
remote authenticated users to conduct cross-site scripting (XSS)
attacks via a crafted file (CVE-2013-5738).

The default configuration of WordPress before 3.6.1 does not prevent
uploads of .swf and .exe files, which might make it easier for remote
authenticated users to conduct cross-site scripting (XSS) attacks via
a crafted file, related to the get_allowed_mime_types function in
wp-includes/functions.php (CVE-2013-5739).

Additionally, php-phpmailer has been updated to a newer version
required by the updated wordpress."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0285.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-phpmailer and / or wordpress packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-phpmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"php-phpmailer-5.2.7-0.20130917.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"wordpress-3.6.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
