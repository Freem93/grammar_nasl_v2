#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:277. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(71031);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/11/25 11:41:42 $");

  script_cve_id("CVE-2013-4508", "CVE-2013-4559", "CVE-2013-4560");
  script_bugtraq_id(63534, 63686, 63688);
  script_xref(name:"MDVSA", value:"2013:277");

  script_name(english:"Mandriva Linux Security Advisory : lighttpd (MDVSA-2013:277)");
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
"Updated lighttpd packages fix security vulnerabilities :

lighttpd before 1.4.34, when SNI is enabled, configures weak SSL
ciphers, which makes it easier for remote attackers to hijack sessions
by inserting packets into the client-server data stream or obtain
sensitive information by sniffing the network (CVE-2013-4508).

In lighttpd before 1.4.34, if setuid() fails for any reason, for
instance if an environment limits the number of processes a user can
have and the target uid already is at the limit, lighttpd will run as
root. A user who can run CGI scripts could clone() often; in this case
a lighttpd restart would end up with lighttpd running as root, and the
CGI scripts would run as root too (CVE-2013-4559).

In lighttpd before 1.4.34, if fam is enabled and there are directories
reachable from configured doc roots and aliases on which
FAMMonitorDirectory fails, a remote client could trigger a DoS
(CVE-2013-4560)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2013-0334.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_auth-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_cml-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_compress-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_magnet-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_mysql_vhost-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_trigger_b4_dl-1.4.30-6.2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lighttpd-mod_webdav-1.4.30-6.2.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
