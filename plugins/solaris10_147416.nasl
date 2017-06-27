#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(71678);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:06:20 $");

  script_cve_id("CVE-2013-0417");

  script_name(english:"Solaris 10 (sparc) : 147416-02");
  script_summary(english:"Check for patch 147416-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 147416-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Sun Storage Common Array Manager (CAM) component
of Oracle Sun Products Suite (subcomponent: Fault Management System
(FMS)). The supported version that is affected is 6.9.0. Easily
exploitable vulnerability allows successful unauthenticated network
attacks via multiple protocols. Successful attack of this
vulnerability can result in unauthorized read access to a subset of
Sun Storage Common Array Manager (CAM) accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147416-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147416-02", obsoleted_by:"", package:"SUNWsefms", version:"6.9.0,REV=2011.11.13.21.31.38") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147416-02", obsoleted_by:"", package:"SUNWstkcamcd", version:"6.9.0,REV=2011.11.13.21.32.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147416-02", obsoleted_by:"", package:"SUNWsesscs", version:"6.9.0,REV=2011.11.13.21.32.51") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147416-02", obsoleted_by:"", package:"SUNWstkraidsa", version:"6.9.0,REV=2011.11.13.21.31.44") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147416-02", obsoleted_by:"", package:"SUNWse6130ui", version:"6.9.0,REV=2011.11.13.21.32.51") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
