#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36045);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_bugtraq_id(34181, 34235);
  script_osvdb_id(52896, 53079);

  script_name(english:"Firefox < 3.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."  );
  script_set_attribute( attribute:"description",   value:
"The installed version of Firefox is earlier than 3.0.8.  Such versions
are potentially affected by the following security issues :

  - An XSL transformation vulnerability can be leveraged 
    with a specially crafted stylesheet to crash the browser
    or to execute arbitrary code. (MFSA 2009-12)

  - An error in the XUL tree method '_moveToEdgeShift()' can
    be leveraged to trigger garbage collection routines on
    objects that are still in use, leading to a browser
    crash and possibly execution of arbitrary code. 
    (MFSA 2009-13)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-13.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.mozilla.com/en-US/firefox/3.0.8/releasenotes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Firefox 3.0.8 or later. "
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/30");
 script_set_attribute(attribute:"patch_publication_date", value: "2009/03/27");
 script_cvs_date("$Date: 2016/05/16 14:12:50 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}


include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.8', severity:SECURITY_HOLE);