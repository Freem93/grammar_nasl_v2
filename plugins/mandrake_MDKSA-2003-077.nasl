#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:077. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14060);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0504");
  script_xref(name:"MDKSA", value:"2003:077");

  script_name(english:"Mandrake Linux Security Advisory : phpgroupware (MDKSA-2003:077)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in all versions of
phpgroupware prior to 0.9.14.006. This latest version fixes an
exploitable condition in all versions that can be exploited remotely
without authentication and can lead to arbitrary code execution on the
web server. This vulnerability is being actively exploited.

Version 0.9.14.005 fixed several other vulnerabilities including
cross-site scripting issues that can be exploited to obtain sensitive
information such as authentication cookies.

This update provides the latest stable version of phpgroupware and all
users are encouraged to update immediately. In addition, you should
also secure your installation by including the following in your
Apache configuration files :

<Directory /var/www/html/phpgroupware> <Files ~ '.inc.php$'> Order
allow,deny Deny from all </Files> </Directory>"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.security-corporation.com/articles-20030702-005.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpgroupware package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpgroupware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", reference:"phpgroupware-0.9.14.006-0.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", reference:"phpgroupware-0.9.14.006-0.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", reference:"phpgroupware-0.9.14.006-0.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
