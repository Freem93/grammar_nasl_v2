#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(27008);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2015/10/20 23:02:22 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-3403", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0453", "CVE-2014-0457", "CVE-2014-0460", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2412", "CVE-2014-2421", "CVE-2014-2427");

  script_name(english:"Solaris 8 (sparc) : 125136-97");
  script_summary(english:"Check for patch 125136-97");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125136-97"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 6: update 101 patch (equivalent to.
Date this patch was last updated by Sun : Jul/13/15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125136-97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6rt", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6jmp", version:"1.6.0,REV=2006.12.07.19.24") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6man", version:"1.6.0,REV=2006.12.07.16.37") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6cfg", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6dmo", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.8", arch:"sparc", patch:"125136-97", obsoleted_by:"152076-05 ", package:"SUNWj6dev", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
