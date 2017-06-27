#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22445);
  script_version("$Revision: 1.49 $");
  script_cvs_date("$Date: 2016/03/22 14:32:26 $");

  script_cve_id("CVE-2012-3123");

  script_name(english:"Solaris 10 (sparc) : 120543-36");
  script_summary(english:"Check for patch 120543-36");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120543-36"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: Apache HTTP Server). The supported version that is
affected is 10. Easily exploitable vulnerability allows successful
unauthenticated network attacks via HTTP. Successful attack of this
vulnerability can result in unauthorized read access to a subset of
Solaris accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120543-36"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120543-36", obsoleted_by:"", package:"SUNWapch2u", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120543-36", obsoleted_by:"", package:"SUNWapch2r", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120543-36", obsoleted_by:"", package:"SUNWapch2S", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"120543-36", obsoleted_by:"", package:"SUNWapch2d", version:"11.10.0,REV=2005.01.08.05.16") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
