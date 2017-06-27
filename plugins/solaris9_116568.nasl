#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(37260);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2004-2765", "CVE-2004-2766");

  script_name(english:"Solaris 9 (sparc) : 116568-99");
  script_summary(english:"Check for patch 116568-99");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 116568-99"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Messaging Server 6.1: core patch.
Date this patch was last updated by Sun : Feb/09/05"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/116568-99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgmf", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgco", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgen", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgwm", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgst", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgmt", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgmp", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsgin", version:"6.0,REV=2003.10.29") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"116568-99", obsoleted_by:"118207-28 120228-20 ", package:"SUNWmsglb", version:"6.0,REV=2003.10.29") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
