#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:103. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82356);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2014-0128", "CVE-2014-3609", "CVE-2014-6270", "CVE-2014-7141", "CVE-2014-7142");
  script_xref(name:"MDVSA", value:"2015:103");

  script_name(english:"Mandriva Linux Security Advisory : squid (MDVSA-2015:103)");
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
"Updated squid packages fix security vulnerabilities :

Due to incorrect state management, Squid before 3.3.12 is vulnerable
to a denial of service attack when processing certain HTTPS requests
if the SSL-Bump feature is enabled (CVE-2014-0128).

Matthew Daley discovered that Squid 3 did not properly perform input
validation in request parsing. A remote attacker could send crafted
Range requests to cause a denial of service (CVE-2014-3609).

Due to incorrect buffer management Squid can be caused by an attacker
to write outside its allocated SNMP buffer (CVE-2014-6270).

Due to incorrect bounds checking Squid pinger binary is vulnerable to
denial of service or information leak attack when processing larger
than normal ICMP or ICMPv6 packets (CVE-2014-7141).

Due to incorrect input validation Squid pinger binary is vulnerable to
denial of service or information leak attacks when processing ICMP or
ICMPv6 packets (CVE-2014-7142)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0396.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squid and / or squid-cachemgr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squid-cachemgr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"squid-3.3.13-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"squid-cachemgr-3.3.13-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
