#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:223. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(69540);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/17 17:13:09 $");

  script_cve_id("CVE-2013-5641", "CVE-2013-5642");
  script_bugtraq_id(62021, 62022);
  script_xref(name:"MDVSA", value:"2013:223");

  script_name(english:"Mandriva Linux Security Advisory : asterisk (MDVSA-2013:223)");
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
"Updated asterisk packages fix security vulnerabilities :

A remotely exploitable crash vulnerability exists in the SIP channel
driver if an ACK with SDP is received after the channel has been
terminated. The handling code incorrectly assumes that the channel
will always be present (CVE-2013-5641).

A remotely exploitable crash vulnerability exists in the SIP channel
driver if an invalid SDP is sent in a SIP request that defines media
descriptions before connection information. The handling code
incorrectly attempts to reference the socket address information even
though that information has not yet been set (CVE-2013-5642)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2013-004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2013-005.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-cel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-corosync");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-fax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-festival");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-jabber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-minivm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-osp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-pktccops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-portaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-saycountpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-skinny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-speex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-unistim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:asterisk-plugins-voicemail-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64asteriskssl1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-addons-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-devel-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-firmware-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-gui-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-alsa-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-calendar-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-cel-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-corosync-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-curl-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-dahdi-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-fax-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-festival-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ices-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-jabber-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-jack-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ldap-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-lua-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-minivm-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mobile-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mp3-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-mysql-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-ooh323-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-osp-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-oss-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-pgsql-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-pktccops-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-portaudio-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-radius-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-saycountpl-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-skinny-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-snmp-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-speex-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-sqlite-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-tds-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-unistim-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-imap-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"asterisk-plugins-voicemail-plain-11.5.1-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64asteriskssl1-11.5.1-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
