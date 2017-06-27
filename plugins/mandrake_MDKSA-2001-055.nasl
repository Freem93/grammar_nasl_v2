#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:055. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13872);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2001-1322");
  script_bugtraq_id(2826, 2840);
  script_osvdb_id(1854, 5542);
  script_xref(name:"MDKSA", value:"2001:055-1");

  script_name(english:"Mandrake Linux Security Advisory : xinetd (MDKSA-2001:055-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A bug exists in xinetd as shipped with Mandrake Linux 8.0 dealing with
TCP connections with the WAIT state that prevents linuxconf-web from
working properly. As well, xinetd contains a security flaw in which it
defaults to a umask of 0. This means that applications using the
xinetd umask that do not set permissions themselves (like SWAT, a web
configuration tool for Samba), will create world-writable files. This
update sets the default umask to 022.

Update :

This update forces the TMPDIR to /tmp instead of obtaining it from the
root user by default, which uses /root/tmp. As well, this version of
xinetd also fixed a possible buffer overflow in the logging code that
was reported by zen-parse on bugtraq, but was not mentioned in the
previous advisory."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xinetd and / or xinetd-ipv6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xinetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xinetd-ipv6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"xinetd-2.3.0-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"xinetd-2.3.0-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"xinetd-ipv6-2.3.0-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
