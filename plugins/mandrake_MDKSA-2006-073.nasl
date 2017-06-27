# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2006:073.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(21280);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:48:07 $");

  script_cve_id("CVE-2006-1721");

  script_name(english:"MDKSA-2006:073 : cyrus-sasl");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the CMU Cyrus Simple Authentication and Security
Layer (SASL) library < 2.1.21, has an unknown impact and remote
unauthenticated attack vectors, related to DIGEST-MD5 negotiation. In
practice, Marcus Meissner found it is possible to crash the
cyrus-imapd daemon with a carefully crafted communication that leaves
out 'realm=...' in the reply or the initial server response.

Updated packages have been patched to address this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2006:073");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/24");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/26");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"cyrus-sasl-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-devel-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-anonymous-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-crammd5-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-digestmd5-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-gssapi-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-login-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-ntlm-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-otp-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-plain-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-sasldb-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-sql-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libsasl2-plug-srp-2.1.19-12.1.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"cyrus-sasl-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2006-1721", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
