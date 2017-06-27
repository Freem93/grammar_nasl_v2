#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:229. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(79589);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/27 12:29:38 $");

  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");
  script_bugtraq_id(70091, 70092, 70093, 70094, 70096);
  script_xref(name:"MDVSA", value:"2014:229");

  script_name(english:"Mandriva Linux Security Advisory : libvncserver (MDVSA-2014:229)");
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
"Updated libvncserver packages fix security vulnerabilities :

A malicious VNC server can trigger incorrect memory management
handling by advertising a large screen size parameter to the VNC
client. This would result in multiple memory corruptions and could
allow remote code execution on the VNC client (CVE-2014-6051,
CVE-2014-6052).

A malicious VNC client can trigger multiple DoS conditions on the VNC
server by advertising a large screen size, ClientCutText message
length and/or a zero scaling factor parameter (CVE-2014-6053,
CVE-2014-6054).

A malicious VNC client can trigger multiple stack-based buffer
overflows by passing a long file and directory names and/or attributes
(FileTime) when using the file transfer message feature
(CVE-2014-6055).

Additionally libvncserver has been built against the new system
minilzo library which is also being provided with this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0397.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lzo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64lzo2_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64minilzo0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vncserver-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vncserver0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:linuxvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64lzo-devel-2.08-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64lzo2_2-2.08-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64minilzo0-2.08-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64vncserver-devel-0.9.9-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64vncserver0-0.9.9-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"linuxvnc-0.9.9-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
