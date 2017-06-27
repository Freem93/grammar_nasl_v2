#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:032. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14016);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/08/09 10:50:40 $");

  script_cve_id("CVE-2003-0085", "CVE-2003-0086");
  script_xref(name:"MDKSA", value:"2003:032");

  script_name(english:"Mandrake Linux Security Advisory : samba (MDKSA-2003:032)");
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
"<p>The SuSE security team, during an audit of the Samba source code,
found a flaw in the main smbd code which could allow an external
attacker to remotely and anonymously gain root privilege on a system
running the Samba server. This flaw exists in all version of Samba 2.x
up to and including 2.2.7a. The Samba team announced 2.2.8 today,
however these updated packages include a patch that corrects this
problem.</p>

<p>MandrakeSoft urges all users to upgrade immediately. If you are
unable to apply the updated packages (perhaps due to unavailability on
your preferred mirror), the following steps can be taken to protect an
unpatched system:</p>

<p>The 'hosts allow' and 'hosts deny' options in the smb.conf file can
be used to allow access to your Samba server by only selected hosts;
for example:</p>

<pre> hosts allow = 127.0.0.1 192.168.2.0/24 192.168.3.0/24 hosts deny
= 0.0.0.0/0 </pre>

<p>This will disallow all connections from machines that are not the
localhost or in the 192.168.2 and 192.168.3 private networks.
Alternatively, you can tell Samba to listen to only specific network
interfaces by using the 'interfaces' and 'bind interfaces only'
options:</p>

<pre> interfaces = eth1 lo bind interfaces only = yes </pre>

<p>Obviously, use the internal interface for your network and not an
external interface connected to the internet. You may also choose to
firewall off some UDP and TCP ports in addition to the previously
mentioned suggestions by blocking external access to ports 137 and 138
(UDP) and ports 139 and 445 (TCP).</p>

<p>These steps should only be used as a temporary preventative measure
and all users should upgrade as quickly as possible.</p>

<p>Thanks to Sebastian Krahmer and the SuSE security team for
performing the audit, Jeremy Allison for providing the fix, and Andrew
Tridgell for providing advice on how to protect an unpatched Samba
system.</p>"
  );
  # http://www.samba.org/samba/whatsnew/samba-2.2.8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.samba.org/samba/history/samba-2.2.10.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-client-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-common-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-doc-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-server-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"samba-swat-2.2.7a-8.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"samba-client-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"samba-common-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"samba-doc-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"samba-server-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"samba-swat-2.2.7a-8.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"nss_wins-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-client-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-common-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-doc-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-server-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-swat-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"samba-winbind-2.2.7a-8.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"nss_wins-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-client-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-common-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-doc-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-server-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-swat-2.2.7a-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"samba-winbind-2.2.7a-8.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
