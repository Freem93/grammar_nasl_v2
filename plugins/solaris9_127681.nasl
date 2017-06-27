#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(67167);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/09 21:14:09 $");

  script_cve_id("CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226");

  script_name(english:"Solaris 9 (sparc) : 127681-07");
  script_summary(english:"Check for patch 127681-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127681-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Management Center 4.0: Patch for Solaris 9.
Date this patch was last updated by Sun : Nov/25/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127681-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWescon", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWesamn", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWesagt", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWesken", version:"4.0,REV=2.9.2007.10.15") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWesclt", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWescom", version:"4.0,REV=2.9.2007.10.23") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWescli", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWesweb", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.9", arch:"sparc", patch:"127681-07", obsoleted_by:"", package:"SUNWessrv", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
