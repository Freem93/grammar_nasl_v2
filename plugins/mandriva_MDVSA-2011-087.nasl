#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:087. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(54288);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/12/18 14:26:56 $");

  script_cve_id("CVE-2011-0904", "CVE-2011-0905");
  script_bugtraq_id(47681);
  script_xref(name:"MDVSA", value:"2011:087");

  script_name(english:"Mandriva Linux Security Advisory : vino (MDVSA-2011:087)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in vino :

The rfbSendFramebufferUpdate function in
server/libvncserver/rfbserver.c in vino-server in Vino 2.x before
2.28.3, 2.32.x before 2.32.2, 3.0.x before 3.0.2, and 3.1.x before
3.1.1, when raw encoding is used, allows remote authenticated users to
cause a denial of service (daemon crash) via a large (1) X position or
(2) Y position value in a framebuffer update request that triggers an
out-of-bounds memory access, related to the rfbTranslateNone and
rfbSendRectEncodingRaw functions (CVE-2011-0904).

The rfbSendFramebufferUpdate function in
server/libvncserver/rfbserver.c in vino-server in Vino 2.x before
2.28.3, 2.32.x before 2.32.2, 3.0.x before 3.0.2, and 3.1.x before
3.1.1, when tight encoding is used, allows remote authenticated users
to cause a denial of service (daemon crash) via crafted dimensions in
a framebuffer update request that triggers an out-of-bounds read
operation (CVE-2011-0905).

The updated packages have been upgraded to 2.28.3 which is not
vulnerable to these isssues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vino package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vino");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"vino-2.28.3-1.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
