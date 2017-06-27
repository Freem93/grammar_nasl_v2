#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:139. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66151);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2012-2118");
  script_bugtraq_id(53150);
  script_xref(name:"MDVSA", value:"2013:139");
  script_xref(name:"MGASA", value:"2012-0299");

  script_name(english:"Mandriva Linux Security Advisory : x11-server (MDVSA-2013:139)");
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
"This fixes a format string vulnerability in the LogVHdrMessageVerb
function in os/log.c when handling input device names in X.Org X11
server (CVE-2012-2118).

MBS1 is not vulnerable to arbitrary code execution via this
vulnerability because of the compiler options that were used to build
it, but it can still cause a crash."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-common-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-devel-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"x11-server-source-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xdmx-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xephyr-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xfake-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xfbdev-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xnest-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xorg-1.11.4-12.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"x11-server-xvfb-1.11.4-12.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
