#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_30983. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include("compat.inc");

if (description)
{
  script_id(17422);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/04/20 00:36:49 $");

  script_cve_id("CVE-2004-0148", "CVE-2005-0547");
  script_xref(name:"HP", value:"emr_na-c00572225");
  script_xref(name:"HP", value:"emr_na-c01035678");
  script_xref(name:"HP", value:"HPSBUX01059");
  script_xref(name:"HP", value:"HPSBUX01119");
  script_xref(name:"HP", value:"SSRT4694");
  script_xref(name:"HP", value:"SSRT4704");

  script_name(english:"HP-UX PHNE_30983 : s700_800 11.23 ftpd(1M) patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 ftpd(1M) patch : 

The remote HP-UX host is affected by multiple vulnerabilities :

  - A potential vulnerability has been identified with HP-UX
    running wu-ftpd with the restricted gid option enabled
    where the vulnerability could be exploited by a local
    user to gain unauthorized access to files. (HPSBUX01059
    SSRT4704)

  - A potential vulnerability has been identified with HP-UX
    running ftpd where the vulnerability could be exploited
    to allow a remote authorized user unauthorized access to
    files. (HPSBUX01119 SSRT4694)"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00572225
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fb36360"
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01035678
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d4b2076"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_30983 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/25");
  script_set_attribute(attribute:"patch_modification_date", value:"2006/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHNE_30983 applies to a different OS release.");
}

patches = make_list("PHNE_30983", "PHNE_31732", "PHNE_32286", "PHNE_33414", "PHNE_34306", "PHNE_34698", "PHNE_36065", "PHNE_36193", "PHNE_38578", "PHNE_38916", "PHNE_40380", "PHNE_41248", "PHNE_41581", "PHNE_42661");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"InternetSrvcs.INETSVCS2-RUN", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
