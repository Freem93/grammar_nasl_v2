#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(19580);
  script_version("$Revision: 1.45 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2009-1099", "CVE-2009-1104", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0453", "CVE-2014-0457", "CVE-2014-0460", "CVE-2014-2398", "CVE-2014-2401", "CVE-2014-2412", "CVE-2014-2421", "CVE-2014-2427");

  script_name(english:"Solaris 10 (x86) : 118669-86");
  script_summary(english:"Check for patch 118669-86");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 118669-86"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 5.0_x86: update 85 patch (equivalent to JDK 5.0u85), 64bit.
Date this patch was last updated by Sun : Apr/13/15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/118669-86"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118669-86", obsoleted_by:"", package:"SUNWj5dmx", version:"1.5.0,REV=2005.03.04.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118669-86", obsoleted_by:"", package:"SUNWj5dvx", version:"1.5.0,REV=2005.03.04.02.15") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"118669-86", obsoleted_by:"", package:"SUNWj5rtx", version:"1.5.0,REV=2005.03.04.02.15") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
