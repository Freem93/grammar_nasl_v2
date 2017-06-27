#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:186. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82486);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/02 13:36:27 $");

  script_cve_id("CVE-2015-2206");
  script_bugtraq_id(72949);
  script_xref(name:"MDVSA", value:"2015:186");

  script_name(english:"Mandriva Linux Security Advisory : phpmyadmin (MDVSA-2015:186)");
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
"A vulnerability has been discovered and corrected in phpmyadmin :

libraries/select_lang.lib.php in phpMyAdmin 4.0.x before 4.0.10.9,
4.2.x before 4.2.13.2, and 4.3.x before 4.3.11.1 includes invalid
language values in unknown-language error responses that contain a
CSRF token and may be sent with HTTP compression, which makes it
easier for remote attackers to conduct a BREACH attack and determine
this token via a series of crafted requests (CVE-2015-2206).

This upgrade provides the latest phpmyadmin version (4.2.13.2) to
address this vulnerability.

Additionally, the phpseclib package has been upgraded to the 0.3.10
version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-1.php"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpmyadmin and / or phpseclib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:phpseclib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
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
if (rpm_check(release:"MDK-MBS1", reference:"phpmyadmin-4.2.13.2-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"phpseclib-0.3.10-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
