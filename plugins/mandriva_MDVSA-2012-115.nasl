#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:115. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61967);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/18 10:44:00 $");

  script_cve_id("CVE-2012-3570", "CVE-2012-3571", "CVE-2012-3954");
  script_bugtraq_id(54665);
  script_xref(name:"MDVSA", value:"2012:115");

  script_name(english:"Mandriva Linux Security Advisory : dhcp (MDVSA-2012:115)");
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
"Multiple vulnerabilities has been discovered and corrected in ISC 
DHCP :

An unexpected client identifier parameter can cause the ISC DHCP
daemon to segmentation fault when running in DHCPv6 mode, resulting in
a denial of service to further client requests. In order to exploit
this condition, an attacker must be able to send requests to the DHCP
server (CVE-2012-3570).

An error in the handling of malformed client identifiers can cause a
DHCP server running affected versions (see Impact) to enter a state
where further client requests are not processed and the server process
loops endlessly, consuming all available CPU cycles. Under normal
circumstances this condition should not be triggered, but a
non-conforming or malicious client could deliberately trigger it in a
vulnerable server. In order to exploit this condition an attacker must
be able to send requests to the DHCP server (CVE-2012-3571).

Two memory leaks have been found and fixed in ISC DHCP. Both are
reproducible when running in DHCPv6 mode (with the -6 command-line
argument.) The first leak is confirmed to only affect servers
operating in DHCPv6 mode, but based on initial code analysis the
second may theoretically affect DHCPv4 servers (though this has not
been demonstrated.) (CVE-2012-3954).

The updated packages have been upgraded to the latest version
(4.2.4-P1) which is not affected by these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", reference:"dhcp-client-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"dhcp-common-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"dhcp-devel-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"dhcp-doc-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"dhcp-relay-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"dhcp-server-4.2.4-0.P1.1.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
