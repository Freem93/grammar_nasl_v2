#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(31333);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2007-2445", "CVE-2007-5266", "CVE-2007-5267", "CVE-2007-5268", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-3964", "CVE-2009-0040");

  script_name(english:"Solaris 10 (sparc) : 137080-07");
  script_summary(english:"Check for patch 137080-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 137080-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: libpng Patch.
Date this patch was last updated by Sun : Jul/18/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/137080-07"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137080-07", obsoleted_by:"", package:"SUNWpng", version:"20.2.6.0,REV=10.0.3.2004.12.15.14.11") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137080-07", obsoleted_by:"", package:"SUNWpngS", version:"20.2.6.0,REV=10.0.3.2004.12.15.14.11") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"137080-07", obsoleted_by:"", package:"SUNWpng-devel", version:"20.2.6.0,REV=10.0.3.2004.12.15.14.11") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
