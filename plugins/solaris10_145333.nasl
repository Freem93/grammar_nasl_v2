#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71659);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2013-3746", "CVE-2015-2616");

  script_name(english:"Solaris 10 (sparc) : 145333-37");
  script_summary(english:"Check for patch 145333-37");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 145333-37"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris Cluster component of Oracle and Sun
Systems Products Suite (subcomponent: Zone Cluster Infrastructure).
Supported versions that are affected are 3.2, 3.3 and 4 prior to 4.1
SRU 3. Easily exploitable vulnerability requiring logon to Operating
System. Successful attack of this vulnerability can result in
unauthorized Operating System takeover including arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/145333-37"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscrtlh", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmd", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWsczu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscdev", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscucm", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWsczr", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmasazu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmasa", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWudlmr", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmasar", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmautil", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscsmf", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscsal", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmasau", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWsctelemetry", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscmasasen", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscr", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscspmu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWcvmr", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWsccomzu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscderby", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscsckr", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWsccomu", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"145333-37", obsoleted_by:"", package:"SUNWscgds", version:"3.3.0,REV=2010.07.26.13.19") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
