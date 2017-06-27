#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(62509);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/30 00:11:55 $");

  script_cve_id("CVE-2012-3165");

  script_name(english:"Solaris 10 (x86) : 127873-02");
  script_summary(english:"Check for patch 127873-02");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127873-02"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Products Suite
(subcomponent: mailx(1)). Supported versions that are affected are 8,
9, 10 and 11. Easily exploitable vulnerability requiring logon to
Operating System. Successful attack of this vulnerability can result
in unauthorized update, insert or delete access to some Solaris
accessible data as well as read access to a subset of Solaris
accessible data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127873-02"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"127873-02", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report());
  else security_note(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
