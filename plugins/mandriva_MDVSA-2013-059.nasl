#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:059. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66073);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/25 11:41:40 $");

  script_cve_id("CVE-2013-2494");
  script_bugtraq_id(58772);
  script_xref(name:"MDVSA", value:"2013:059");

  script_name(english:"Mandriva Linux Security Advisory : dhcp (MDVSA-2013:059)");
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
"A security issue was identified and fixed in ISC DHCP :

libdns in ISC DHCP 4.2.x before 4.2.5-P1 allows remote name servers to
cause a denial of service (memory consumption) via vectors involving a
regular expression, as demonstrated by a memory-exhaustion attack
against a machine running a dhcpd process, a related issue to
CVE-2013-2266 (CVE-2013-2494).

The updated packages have upgraded to the 4.2.5-P1 version which is
not vulnerable to this issue"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-client-4.2.5P1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-common-4.2.5P1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-devel-4.2.5P1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-doc-4.2.5P1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-relay-4.2.5P1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dhcp-server-4.2.5P1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
