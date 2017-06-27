#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:072. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66086);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/26 11:21:54 $");

  script_cve_id("CVE-2012-3411", "CVE-2013-0198");
  script_bugtraq_id(54353, 57458);
  script_xref(name:"MDVSA", value:"2013:072");
  script_xref(name:"MGASA", value:"2012-0273");
  script_xref(name:"MGASA", value:"2013-0030");

  script_name(english:"Mandriva Linux Security Advisory : dnsmasq (MDVSA-2013:072)");
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
"Updated dnsmasq packages fix security vulnerabilities :

When dnsmasq before 2.63 is used in conjunctions with certain
configurations of libvirtd, network packets from prohibited networks
(e.g. packets that should not be passed in) may be sent to the dnsmasq
application and processed. This can result in DNS amplification
attacks for example (CVE-2012-3411).

This update adds a new option --bind-dynamic which is immune to this
problem.

Updated dnsmasq packages fix security vulnerabilities 
(CVE-2013-0198) :

This update completes the fix for CVE-2012-3411 provided with
dnsmasq-2.63. It was found that after the upstream patch for
CVE-2012-3411 issue was applied, dnsmasq still :

  - replied to remote TCP-protocol based DNS queries (UDP
    protocol ones were corrected, but TCP ones not) from
    prohibited networks, when the --bind-dynamic option was
    used,

  - when --except-interface lo option was used dnsmasq
    didn't answer local or remote UDP DNS queries, but still
    allowed TCP protocol based DNS queries,

  - when --except-interface lo option was not used local /
    remote TCP DNS queries were also still answered by
    dnsmasq.

This update fix these three cases."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq and / or dnsmasq-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:dnsmasq-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dnsmasq-2.63-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"dnsmasq-base-2.63-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
