#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:178. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66978);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/12/09 14:21:16 $");

  script_cve_id("CVE-2013-1923");
  script_bugtraq_id(58854);
  script_xref(name:"MDVSA", value:"2013:178");

  script_name(english:"Mandriva Linux Security Advisory : nfs-utils (MDVSA-2013:178)");
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
"Updated nfs-utils packages fix security vulnerability

It was reported that rpc.gssd in nfs-utils is vulnerable to DNS
spoofing due to it depending on PTR resolution for GSSAPI
authentication. Because of this, if a user where able to poison DNS to
a victim's computer, they would be able to trick rpc.gssd into talking
to another server (perhaps with less security) than the intended
server (with stricter security). If the victim has write access to the
second (less secure) server, and the attacker has read access (when
they normally might not on the secure server), the victim could write
files to that server, which the attacker could obtain (when normally
they would not be able to). To the victim this is transparent because
the victim's computer asks the KDC for a ticket to the second server
due to reverse DNS resolution; in this case Krb5 authentication does
not fail because the victim is talking to the correct server
(CVE-2013-1923)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0178.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfs-utils and / or nfs-utils-clients packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nfs-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nfs-utils-clients");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nfs-utils-1.2.5-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"nfs-utils-clients-1.2.5-2.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
