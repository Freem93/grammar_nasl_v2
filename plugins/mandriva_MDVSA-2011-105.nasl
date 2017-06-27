#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:105. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54940);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/03/11 17:42:31 $");

  script_cve_id(
    "CVE-2011-1957",
    "CVE-2011-1958",
    "CVE-2011-1959",
    "CVE-2011-2174",
    "CVE-2011-2175"
  );
  script_bugtraq_id(48066);
  script_osvdb_id(
    72975,
    72976,
    72977,
    72978,
    72979
  );
  script_xref(name:"MDVSA", value:"2011:105");

  script_name(english:"Mandriva Linux Security Advisory : wireshark (MDVSA-2011:105)");
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
"This advisory updates wireshark to the latest version (1.2.17), fixing
several security issues :

  - Large/infinite loop in the DICOM dissector. (Bug 5876)
    Versions affected: 1.2.0 to 1.2.16 and 1.4.0 to 1.4.6.

  - Huzaifa Sidhpurwala of the Red Hat Security Response
    Team discovered that a corrupted Diameter dictionary
    file could crash Wireshark. Versions affected: 1.2.0 to
    1.2.16 and 1.4.0 to 1.4.6.

  - Huzaifa Sidhpurwala of the Red Hat Security Response
    Team discovered that a corrupted snoop file could crash
    Wireshark. (Bug 5912) Versions affected: 1.2.0 to 1.2.16
    and 1.4.0 to 1.4.6.

  - David Maciejak of Fortinet's FortiGuard Labs discovered
    that malformed compressed capture data could crash
    Wireshark. (Bug 5908) Versions affected: 1.2.0 to 1.2.16
    and 1.4.0 to 1.4.6.

  - Huzaifa Sidhpurwala of the Red Hat Security Response
    Team discovered that a corrupted Visual Networks file
    could crash Wireshark. (Bug 5934) Versions affected:
    1.2.0 to 1.2.16 and 1.4.0 to 1.4.6."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2011-07.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dumpcap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wireshark0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwireshark0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rawshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wireshark-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
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
if (rpm_check(release:"MDK2010.1", reference:"dumpcap-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wireshark-devel-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wireshark0-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwireshark-devel-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwireshark0-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"rawshark-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"tshark-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"wireshark-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"wireshark-tools-1.2.17-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
