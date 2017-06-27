#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:160. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66313);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-3238", "CVE-2013-3239");
  script_bugtraq_id(59460, 59465);
  script_xref(name:"MDVSA", value:"2013:160");
  script_xref(name:"MGASA", value:"2013-0133");

  script_name(english:"Mandriva Linux Security Advisory : phpmyadmin (MDVSA-2013:160)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated phpmyadmin package fixes security vulnerabilities :

In some PHP versions, the preg_replace\(\) function can be tricked
into executing arbitrary PHP code on the server. This is done by
passing a crafted argument as the regular expression, containing a
null byte. phpMyAdmin does not correctly sanitize an argument passed
to preg_replace\(\) when using the Replace table prefix feature,
opening the way to this vulnerability (CVE-2013-3238).

phpMyAdmin can be configured to save an export file on the web server,
via its SaveDir directive. With this in place, it's possible, either
via a crafted filename template or a crafted table name, to save a
double extension file like foobar.php.sql. In turn, an Apache
webserver on which there is no definition for the MIME type sql (the
default) will treat this saved file as a .php script, leading to
remote code execution (CVE-2013-3239)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpmyadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpMyAdmin Authenticated Remote Code Execution via preg_replace()');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");
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
if (rpm_check(release:"MDK-MBS1", reference:"phpmyadmin-3.5.8.1-0.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
