#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22988);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2016/12/12 14:59:32 $");

  script_cve_id("CVE-2009-0278", "CVE-2009-2625", "CVE-2011-3559");
  script_xref(name:"IAVT", value:"2009-T-0009");

  script_name(english:"Solaris 10 (x86) : 119167-43");
  script_summary(english:"Check for patch 119167-43");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119167-43"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java System App Server Enterprise Ed 8.1 2005Q1, _x86 Patch32.
Date this patch was last updated by Sun : Oct/18/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119167-43"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasut", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasuee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasman", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascmnse", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasjdoc", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasacee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWaslb", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascml", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasu", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasdem", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascmn", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWashdm", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWaswbcr", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasac", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasmanee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasdemdb", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
