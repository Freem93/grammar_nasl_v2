#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:126. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(76423);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/09 16:15:31 $");

  script_cve_id("CVE-2014-4348", "CVE-2014-4349");
  script_bugtraq_id(68201, 68205);
  script_xref(name:"MDVSA", value:"2014:126");

  script_name(english:"Mandriva Linux Security Advisory : phpmyadmin (MDVSA-2014:126)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in
phpmyadmin :

Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
4.2.x before 4.2.4 allow remote authenticated users to inject
arbitrary web script or HTML via a crafted (1) database name or (2)
table name that is improperly handled after presence in (a) the
favorite list or (b) recent tables (CVE-2014-4348).

Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
4.1.x before 4.1.14.1 and 4.2.x before 4.2.4 allow remote
authenticated users to inject arbitrary web script or HTML via a
crafted table name that is improperly handled after a (1) hide or (2)
unhide action (CVE-2014-4349).

This upgrade provides the latest phpmyadmin version (4.2.5) to address
these vulnerabilities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sourceforge.net/p/phpmyadmin/news/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-2.php"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2014-3.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpmyadmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/09");
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
if (rpm_check(release:"MDK-MBS1", reference:"phpmyadmin-4.2.5-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
