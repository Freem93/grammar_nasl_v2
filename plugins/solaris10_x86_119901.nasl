#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(22992);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/09 21:04:55 $");

  script_cve_id("CVE-2009-2285", "CVE-2009-2347", "CVE-2012-5581");
  script_bugtraq_id(56715);
  script_osvdb_id(88155);

  script_name(english:"Solaris 10 (x86) : 119901-17");
  script_summary(english:"Check for patch 119901-17");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119901-17"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0_x86: GNOME libtiff - library for reading and writing T.
Date this patch was last updated by Sun : Sep/15/16"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119901-17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"You should install this patch for your system to be up-to-date."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sun:solaris");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/06");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119901-17", obsoleted_by:"", package:"SUNWTiff", version:"20.2.6.0,REV=10.0.3.2004.12.16.14.41") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119901-17", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.16.14.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119901-17", obsoleted_by:"", package:"SUNWTiff-devel", version:"20.2.6.0,REV=10.0.3.2004.12.16.14.41") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119901-17", obsoleted_by:"", package:"SUNWgnome-img-viewer-share", version:"2.6.0,REV=10.0.3.2004.12.16.19.00") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_HOST_NOT, "affected");
