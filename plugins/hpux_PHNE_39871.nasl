#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_39871. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(40364);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/02 13:36:27 $");

  script_cve_id("CVE-2009-0159");
  script_bugtraq_id(34481, 35017);
  script_osvdb_id(53593, 54576);
  script_xref(name:"HP", value:"emr_na-c01763606");
  script_xref(name:"HP", value:"HPSBUX02437");
  script_xref(name:"HP", value:"SSRT090038");

  script_name(english:"HP-UX PHNE_39871 : HP-UX Running XNTP, Remote Execution of Arbitrary Code (HPSBUX02437 SSRT090038 rev.2)");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.11 NTP timeservices upgrade plus utilities : 

A potential security vulnerability has been identified with HP-UX
running XNTP. The vulnerability could be exploited remotely to execute
arbitrary code."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01763606
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08444db8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_39871 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/13");
  script_set_attribute(attribute:"patch_modification_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.11"))
{
  exit(0, "The host is not affected since PHNE_39871 applies to a different OS release.");
}

patches = make_list("PHNE_39871", "PHNE_41907", "PHNE_44235");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS-BOOT", version:"B.11.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
