#%NASL_MIN_LEVEL 99999
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandriva Linux Security Advisory MDVA-2009:183.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(42405);
  script_version("$Revision: 1.8 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:183 : nvidia");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"This update provides the kernel modules which were not distributed
with the last kernel update.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:183");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/05");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/11/06");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"em8300-kernel-2.6.24.7-desktop-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-2.6.24.7-desktop586-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-2.6.24.7-laptop-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-2.6.24.7-server-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-desktop586-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-desktop-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-laptop-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-server-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-2.6.24.7-desktop-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-2.6.24.7-desktop586-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-2.6.24.7-laptop-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-2.6.24.7-server-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-desktop586-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-desktop-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-laptop-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl2-kernel-server-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-2.6.24.7-desktop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-2.6.24.7-desktop586-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-2.6.24.7-laptop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-2.6.24.7-server-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-desktop586-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-desktop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-laptop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdsl-kernel-server-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-2.6.24.7-desktop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-2.6.24.7-desktop586-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-2.6.24.7-laptop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-2.6.24.7-server-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-desktop586-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-desktop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-laptop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslsl-kernel-server-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-2.6.24.7-desktop-3mnb-3.11.05-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-2.6.24.7-desktop586-3mnb-3.11.05-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-2.6.24.7-laptop-3mnb-3.11.05-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-2.6.24.7-server-3mnb-3.11.05-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-desktop586-latest-3.11.05-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-desktop-latest-3.11.05-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-laptop-latest-3.11.05-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslslusb-kernel-server-latest-3.11.05-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-2.6.24.7-desktop-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-2.6.24.7-desktop586-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-2.6.24.7-laptop-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-2.6.24.7-server-3mnb-3.11.07-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-desktop586-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-desktop-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-laptop-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb2-kernel-server-latest-3.11.07-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-2.6.24.7-desktop-3mnb-3.11.05-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-2.6.24.7-desktop586-3mnb-3.11.05-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-2.6.24.7-laptop-3mnb-3.11.05-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-2.6.24.7-server-3mnb-3.11.05-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-desktop586-latest-3.11.05-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-desktop-latest-3.11.05-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-laptop-latest-3.11.05-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusba-kernel-server-latest-3.11.05-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-2.6.24.7-desktop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-2.6.24.7-desktop586-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-2.6.24.7-laptop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-2.6.24.7-server-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-desktop586-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-desktop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-laptop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcdslusb-kernel-server-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-2.6.24.7-desktop-3mnb-3.11.07-6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-2.6.24.7-desktop586-3mnb-3.11.07-6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-2.6.24.7-laptop-3mnb-3.11.07-6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-2.6.24.7-server-3mnb-3.11.07-6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20091103.6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-desktop-latest-3.11.07-1.20091103.6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-laptop-latest-3.11.07-1.20091103.6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcpci-kernel-server-latest-3.11.07-1.20091103.6.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-2.6.24.7-desktop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-2.6.24.7-desktop586-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-2.6.24.7-laptop-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-2.6.24.7-server-3mnb-3.11.07-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-desktop586-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-desktop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-laptop-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb2-kernel-server-latest-3.11.07-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-2.6.24.7-desktop-3mnb-3.11.04-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-2.6.24.7-desktop586-3mnb-3.11.04-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-2.6.24.7-laptop-3mnb-3.11.04-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-2.6.24.7-server-3mnb-3.11.04-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-desktop586-latest-3.11.04-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-desktop-latest-3.11.04-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-laptop-latest-3.11.04-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fcusb-kernel-server-latest-3.11.04-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-desktop-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-desktop586-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-laptop-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-server-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-desktop586-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-desktop-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-laptop-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-server-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-2.6.24.7-desktop-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-2.6.24.7-desktop586-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-2.6.24.7-laptop-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-2.6.24.7-server-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-desktop586-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-desktop-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-laptop-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb_CZ-kernel-server-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-2.6.24.7-desktop-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-2.6.24.7-desktop586-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-2.6.24.7-laptop-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-2.6.24.7-server-3mnb-3.11.06-6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-desktop586-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-desktop-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-laptop-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"fxusb-kernel-server-latest-3.11.06-1.20091103.6mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-2.6.24.7-desktop-3mnb-1.13-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-2.6.24.7-desktop586-3mnb-1.13-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-2.6.24.7-laptop-3mnb-1.13-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-2.6.24.7-server-3mnb-1.13-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-desktop586-latest-1.13-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-desktop-latest-1.13-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-laptop-latest-1.13-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hcfpcimodem-kernel-server-latest-1.13-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-desktop-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-desktop586-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-laptop-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-server-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-desktop586-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-desktop-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-laptop-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-server-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-desktop-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-desktop586-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-laptop-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-server-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-desktop586-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-desktop-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-laptop-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-server-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-desktop-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-desktop586-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-laptop-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-server-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-desktop586-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-desktop-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-laptop-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-server-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-desktop-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-desktop586-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-laptop-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-server-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-desktop586-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-desktop-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-laptop-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-server-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-desktop-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-desktop586-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-laptop-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-server-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-desktop586-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-desktop-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-laptop-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-server-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-desktop-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-desktop586-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-laptop-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-server-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-desktop586-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-desktop-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-laptop-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-server-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-desktop-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-desktop586-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-laptop-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-server-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-desktop586-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-desktop-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-laptop-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-server-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-desktop-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-desktop586-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-laptop-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-server-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-desktop586-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-desktop-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-laptop-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-server-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-desktop-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-desktop586-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-laptop-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-server-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-desktop586-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-desktop-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-laptop-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-server-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-desktop-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-desktop586-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-laptop-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-server-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-desktop586-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-desktop-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-laptop-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-server-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-2.6.24.7-desktop-3mnb-2.9.11-0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-2.6.24.7-desktop586-3mnb-2.9.11-0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-2.6.24.7-laptop-3mnb-2.9.11-0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-2.6.24.7-server-3mnb-2.9.11-0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20091103.0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-desktop-latest-2.9.11-1.20091103.0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-laptop-latest-2.9.11-1.20091103.0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"slmodem-kernel-server-latest-2.9.11-1.20091103.0.20070813.3mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-2.6.24.7-desktop-3mnb-0.9.3-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-2.6.24.7-desktop586-3mnb-0.9.3-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-2.6.24.7-laptop-3mnb-0.9.3-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-2.6.24.7-server-3mnb-0.9.3-7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-desktop586-latest-0.9.3-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-desktop-latest-0.9.3-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-laptop-latest-0.9.3-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unicorn-kernel-server-latest-0.9.3-1.20091103.7mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-desktop-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-desktop586-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-laptop-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-server-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-desktop586-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-desktop-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-laptop-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-server-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-2.6.24.7-desktop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-2.6.24.7-desktop586-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-2.6.24.7-laptop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-2.6.24.7-server-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-desktop586-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-desktop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-laptop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxadd-kernel-server-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-2.6.24.7-desktop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-2.6.24.7-desktop586-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-2.6.24.7-laptop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-2.6.24.7-server-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-desktop586-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-desktop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-laptop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vboxvfs-kernel-server-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-desktop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-desktop586-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-laptop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-server-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-desktop586-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-desktop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-laptop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-server-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-desktop-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-desktop586-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-laptop-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-server-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-desktop586-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-laptop-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"em8300-kernel-2.6.24.7-desktop-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-2.6.24.7-laptop-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-2.6.24.7-server-3mnb-0.16.4-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-desktop-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-laptop-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"em8300-kernel-server-latest-0.16.4-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-desktop-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-laptop-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-2.6.24.7-server-3mnb-8.471-3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-desktop-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-laptop-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"fglrx-kernel-server-latest-8.471-1.20091103.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-desktop-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-laptop-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-2.6.24.7-server-3mnb-7.68.00.07-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-desktop-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-laptop-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"hsfmodem-kernel-server-latest-7.68.00.07-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-desktop-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-laptop-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-2.6.24.7-server-3mnb-1.3.0pre11-15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-desktop-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-laptop-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"kqemu-kernel-server-latest-1.3.0pre11-1.20091103.15", release:"MDK2008.1", cpu:"x86_64", yank:"mdk")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-desktop-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-laptop-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-2.6.24.7-server-3mnb-1.4.6-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-desktop-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-laptop-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"libafs-kernel-server-latest-1.4.6-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-desktop-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-laptop-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-2.6.24.7-server-3mnb-0.8.2-1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-desktop-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-laptop-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lirc-kernel-server-latest-0.8.2-1.20091103.1.20080310.2.3mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-desktop-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-laptop-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-2.6.24.7-server-3mnb-4.43-21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-desktop-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-laptop-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lzma-kernel-server-latest-4.43-1.20091103.21mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-desktop-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-laptop-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-2.6.24.7-server-3mnb-0.9.3.3-5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-desktop-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-laptop-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"madwifi-kernel-server-latest-0.9.3.3-1.20091103.5.r3114mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-desktop-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-laptop-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-2.6.24.7-server-3mnb-1.52-2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-desktop-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-laptop-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ndiswrapper-kernel-server-latest-1.52-1.20091103.2.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-desktop-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-laptop-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-2.6.24.7-server-3mnb-71.86.04-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-desktop-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-laptop-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia71xx-kernel-server-latest-71.86.04-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-desktop-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-laptop-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-2.6.24.7-server-3mnb-96.43.05-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-desktop-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-laptop-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia96xx-kernel-server-latest-96.43.05-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-desktop-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-laptop-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-2.6.24.7-server-3mnb-169.12-4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-desktop-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-laptop-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"nvidia-current-kernel-server-latest-169.12-1.20091103.4mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-desktop-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-laptop-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-2.6.24.7-server-3mnb-1.4.1mdv2008.1-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-desktop-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-laptop-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"unionfs-kernel-server-latest-1.4.1mdv2008.1-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-desktop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-laptop-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-2.6.24.7-server-3mnb-1.5.6-1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-desktop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-laptop-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"virtualbox-kernel-server-latest-1.5.6-1.20091103.1.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-desktop-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-laptop-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-2.6.24.7-server-3mnb-4.8.01.0640-1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-laptop-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20091103.1mdv2008.1", release:"MDK2008.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}
