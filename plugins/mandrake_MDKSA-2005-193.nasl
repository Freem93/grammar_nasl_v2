#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:193. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20435);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2005-3184", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3245", "CVE-2005-3246", "CVE-2005-3247", "CVE-2005-3248", "CVE-2005-3249", "CVE-2005-3313");
  script_bugtraq_id(15148);
  script_xref(name:"MDKSA", value:"2005:193-2");

  script_name(english:"Mandrake Linux Security Advisory : ethereal (MDKSA-2005:193-2)");
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
"Ethereal 0.10.13 is now available fixing a number of security
vulnerabilities in various dissectors :

  - the ISAKMP dissector could exhaust system memory

    - the FC-FCS dissector could exhaust system memory

    - the RSVP dissector could exhaust system memory

    - the ISIS LSP dissector could exhaust system memory

    - the IrDA dissector could crash

    - the SLIMP3 dissector could overflow a buffer

    - the BER dissector was susceptible to an infinite loop

    - the SCSI dissector could dereference a NULL pointer
      and crash

    - the sFlow dissector could dereference a NULL pointer
      and crash

    - the RTnet dissector could dereference a NULL pointer
      and crash

    - the SigComp UDVM could go into an infinite loop or
      crash

    - the X11 dissector could attempt to divide by zero

    - if SMB transaction payload reassembly is enabled the
      SMB dissector could crash (by default this is
      disabled)

  - if the 'Dissect unknown RPC program numbers' option was
    enabled, the ONC RPC dissector might be able to exhaust
    system memory (by default this is disabled)

  - the AgentX dissector could overflow a buffer

    - the WSP dissector could free an invalid pointer

    - iDEFENSE discovered a buffer overflow in the SRVLOC
      dissector

The new version of Ethereal is provided and corrects all of these
issues.

An infinite loop in the IRC dissector was also discovered and fixed
after the 0.10.13 release. The updated packages include the fix.

Update :

A permissions problem on the /usr/share/ethereal/dtds directory caused
errors when ethereal started as a non-root user. This update corrects
the problem."
  );
  # http://www.ethereal.com/appnotes/enpa-sa-00021.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://ethereal.archive.sunet.se/appnotes/enpa-sa-00021.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ethereal-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libethereal0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.2", reference:"ethereal-0.10.13-0.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"ethereal-tools-0.10.13-0.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64ethereal0-0.10.13-0.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libethereal0-0.10.13-0.4.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tethereal-0.10.13-0.4.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"ethereal-0.10.13-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"ethereal-tools-0.10.13-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64ethereal0-0.10.13-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libethereal0-0.10.13-0.4.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tethereal-0.10.13-0.4.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
