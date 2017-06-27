#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:123. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(74481);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id("CVE-2013-7295", "CVE-2014-0160");
  script_bugtraq_id(64651, 66690);
  script_xref(name:"MDVSA", value:"2014:123");

  script_name(english:"Mandriva Linux Security Advisory : tor (MDVSA-2014:123)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tor packages fix multiple vulnerabilities :

Tor before 0.2.4.20, when OpenSSL 1.x is used in conjunction with a
certain HardwareAccel setting on Intel Sandy Bridge and Ivy Bridge
platforms, does not properly generate random numbers for relay
identity keys and hidden-service identity keys, which might make it
easier for remote attackers to bypass cryptographic protection
mechanisms via unspecified vectors (CVE-2013-7295).

Update to version 0.2.4.22 solves these major and security problems :

  - Block authority signing keys that were used on
    authorities vulnerable to the heartbleed bug in OpenSSL
    (CVE-2014-0160).

  - Fix a memory leak that could occur if a microdescriptor
    parse fails during the tokenizing step.

  - The relay ciphersuite list is now generated
    automatically based on uniform criteria, and includes
    all OpenSSL ciphersuites with acceptable strength and
    forward secrecy.

  - Relays now trust themselves to have a better view than
    clients of which TLS ciphersuites are better than
    others.

  - Clients now try to advertise the same list of
    ciphersuites as Firefox 28.

For other changes see the upstream change log"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0256.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"tor-0.2.4.22-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
