#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:073. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(53369);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-0997");
  script_bugtraq_id(47176);
  script_xref(name:"MDVSA", value:"2011:073");

  script_name(english:"Mandriva Linux Security Advisory : dhcp (MDVSA-2011:073)");
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
"A vulnerability has been found and corrected in ISC DHCP :

dhclient in ISC DHCP 3.0.x through 4.2.x before 4.2.1-P1, 3.1-ESV
before 3.1-ESV-R1, and 4.1-ESV before 4.1-ESV-R2 allows remote
attackers to execute arbitrary commands via shell metacharacters in a
hostname obtained from a DHCP message (CVE-2011-0997).

Additionally for Corporate Server 4 and Enterprise Server 5 ISC DHCP
has been upgraded from the 3.0.7 version to the 4.1.2-P1 version which
brings many enhancements such as better ipv6 support.

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have upgraded to the 4.1.2-P1 version and patched
to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://ftp.isc.org/isc/dhcp/dhcp-4.1.2-P1-RELNOTES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.isc.org/software/dhcp/advisories/CVE-2011-0997"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"dhcp-client-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dhcp-common-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dhcp-devel-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dhcp-doc-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dhcp-relay-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"dhcp-server-4.1.2-0.4mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"dhcp-client-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dhcp-common-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dhcp-devel-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dhcp-doc-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dhcp-relay-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"dhcp-server-4.1.2-0.4mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"dhcp-client-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dhcp-common-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dhcp-devel-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dhcp-doc-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dhcp-relay-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"dhcp-server-4.1.2-0.4mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
