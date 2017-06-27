#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:171. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61935);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-2176", "CVE-2011-3364");
  script_bugtraq_id(48396, 49785);
  script_xref(name:"MDVSA", value:"2011:171");

  script_name(english:"Mandriva Linux Security Advisory : networkmanager (MDVSA-2011:171)");
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
"Security issues were identified and fixed in networkmanager :

GNOME NetworkManager before 0.8.6 does not properly enforce the
auth_admin element in PolicyKit, which allows local users to bypass
intended wireless network sharing restrictions via unspecified vectors
(CVE-2011-2176).

Incomplete blacklist vulnerability in the svEscape function in
settings/plugins/ifcfg-rh/shvar.c in the ifcfg-rh plug-in for GNOME
NetworkManager 0.9.1, 0.9.0, 0.8.1, and possibly other versions, when
PolicyKit is configured to allow users to create new connections,
allows local users to execute arbitrary commands via a newline
character in the name for a new network connection, which is not
properly handled when writing to the ifcfg file (CVE-2011-3364).

Instead of patching networkmanager, the latest 0.8.6.0 stable version
is being provided due to the large amount of bugs fixed upstream. Also
the networkmanager-applet, networkmanager-openconnect,
networkmanager-openvpn, networkmanager-pptp, networkmanager-vpnc is
being provided with their latest 0.8.6.0 stable versions.

The provided packages solves these security vulnerabilities."
  );
  # http://cgit.freedesktop.org/NetworkManager/NetworkManager/plain/NEWS?h=NM_0_8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9724a75d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-glib-vpn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-glib-vpn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64nm-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-glib-vpn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-glib-vpn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnm-util1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager-openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager-openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:networkmanager-vpnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-glib-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-glib-vpn-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-glib-vpn1-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-glib2-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-util-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64nm-util1-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-glib-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-glib-vpn-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-glib-vpn1-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-glib2-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-util-devel-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libnm-util1-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-applet-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-openconnect-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-openvpn-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-pptp-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"networkmanager-vpnc-0.8.6.0-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
